//go:build ignore
// FESS optional XDP ingress prefilter. No TCP termination or HTTP inspection.
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define INLINE static __attribute__((always_inline)) inline
#define PASS 2
#define DROP 1
struct xdp_md { u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex; };
static void *(*lookup)(void *,const void *)=(void *)1;
static long (*update)(void *,const void *,const void *,u64)=(void *)2;
static u64 (*ktime_ns)(void)=(void *)5;
struct bpf_spin_lock {u32 val;};
static long (*spin_lock)(struct bpf_spin_lock *)=(void *)93;
static long (*spin_unlock)(struct bpf_spin_lock *)=(void *)94;
struct prefix4 {u32 bits; u8 addr[4];};
struct prefix6 {u32 bits; u8 addr[16];};
struct source {u32 family; u8 addr[16];};
// Keep field order synchronized with limits in runner_linux.go.
struct limits {
 u32 packets_per_sec, syns_per_sec, drop_fragments;
 u32 global_pps, global_packet_burst, global_bps, global_byte_burst, global_syns, global_syn_burst;
 u32 icmp_pps, icmp_burst, icmp_ip_pps, icmp_ip_burst;
 u32 invalid_lengths, invalid_flags, temporary_blocks;
};
struct budget {u64 packets;u64 syns;};
struct bucket {u64 at;u64 credit;};
struct token_budget {struct bpf_spin_lock lock;u32 pad;struct bucket packets,bytes,syns;};
#define TRIE(name, keytype) struct {__uint(type,11);__uint(max_entries,16384);__uint(map_flags,1);__type(key,keytype);__type(value,u32);} name SEC(".maps")
TRIE(block4,struct prefix4); TRIE(block6,struct prefix6);
TRIE(allow4,struct prefix4); TRIE(allow6,struct prefix6);
struct {__uint(type,1);__uint(max_entries,4096);__type(key,u32);__type(value,u32);} ports SEC(".maps");
struct {__uint(type,2);__uint(max_entries,1);__type(key,u32);__type(value,struct limits);} config SEC(".maps");
struct {__uint(type,9);__uint(max_entries,65536);__type(key,struct source);__type(value,struct budget);} rates SEC(".maps");
struct {__uint(type,2);__uint(max_entries,2);__type(key,u32);__type(value,struct token_budget);} shared_budgets SEC(".maps");
struct {__uint(type,9);__uint(max_entries,65536);__type(key,struct source);__type(value,u64);} echo_rates SEC(".maps");
struct {__uint(type,9);__uint(max_entries,65536);__type(key,struct source);__type(value,u64);} temporary_bans SEC(".maps");
struct {__uint(type,6);__uint(max_entries,10);__type(key,u32);__type(value,u64);} counters SEC(".maps");
INLINE void count(u32 key){u64 *v=lookup(&counters,&key);if(v)(*v)++;}
INLINE int passed(void){count(1);return PASS;}
INLINE int unparsed(void){count(5);return passed();}
INLINE int dropped(u32 reason){count(reason);return DROP;}
INLINE u16 read16(const u8 *p){return ((u16)p[0]<<8)|p[1];}
INLINE int allowed(struct source *src){
 if(src->family==4){struct prefix4 k={.bits=32};__builtin_memcpy(k.addr,src->addr,4);return lookup(&allow4,&k)!=0;}
 struct prefix6 k={.bits=128};__builtin_memcpy(k.addr,src->addr,16);return lookup(&allow6,&k)!=0;
}
// Credit is in billionths of a token. Cap elapsed time before multiplying to
// avoid overflow, retain fractional refill, and serialize across all RX CPUs.
// Only called while holding the map value's spin lock; no helpers inside.
INLINE int token(struct bucket *b,u64 now,u32 rate,u32 burst,u32 cost){
 if(!rate)return 1;
 u64 cap=(u64)burst*1000000000ULL;
 if(!b->at){b->at=now;b->credit=cap;}
 u64 elapsed=now>b->at?now-b->at:0;
 u64 full=(cap+(u64)rate-1)/(u64)rate;
 if(elapsed>=full)b->credit=cap;
 else {u64 refill=elapsed*(u64)rate;b->credit=b->credit+refill;if(b->credit>cap)b->credit=cap;}
 if(now>b->at)b->at=now;
 u64 need=(u64)cost*1000000000ULL;
 if(b->credit<need)return 0;
 b->credit-=need;return 1;
}
INLINE int global_budget(struct limits *cfg,u32 length,u32 syn,u64 now){
 if(!cfg->global_pps&&!cfg->global_bps&&!cfg->global_syns)return 1;
 u32 key=0;struct token_budget *b=lookup(&shared_budgets,&key);if(!b)return 0;
 spin_lock(&b->lock);
 int ok=token(&b->packets,now,cfg->global_pps,cfg->global_packet_burst,1);
 ok &= token(&b->bytes,now,cfg->global_bps,cfg->global_byte_burst,length);
 if(syn)ok &= token(&b->syns,now,cfg->global_syns,cfg->global_syn_burst,1);
 spin_unlock(&b->lock);return ok;
}
// Existing per-source limits retain their fixed-second semantics.
INLINE int consume(u64 *slot,u32 now,u32 limit){
 if(!limit)return 1;
 #pragma unroll
 for(int i=0;i<8;i++){
  u64 old=*slot;u32 used=(u32)old;
  if((u32)(old>>32)!=now)used=0;
  if(used>=limit)return 0;
  u64 next=((u64)now<<32)|(u64)(used+1);
  if(__sync_val_compare_and_swap(slot,old,next)==old)return 1;
 }
 return 0;
}
INLINE int echo(struct source *src,const u8 *l4,const u8 *end,struct limits *cfg,u32 available){
 // Rate-limit Echo Requests only. Error messages, NDP and Echo Replies pass.
 if(!cfg||(!cfg->icmp_pps&&!cfg->icmp_ip_pps))return passed();
 if(l4+8>end||available<8)return unparsed();
 if(l4[0]!=(src->family==4?8:128)||l4[1]!=0)return passed();
 if(allowed(src))return passed();
 u64 now=ktime_ns();
 if(cfg->icmp_pps){
  u32 key=1;struct token_budget *b=lookup(&shared_budgets,&key);if(!b)return dropped(7);
  spin_lock(&b->lock);int ok=token(&b->packets,now,cfg->icmp_pps,cfg->icmp_burst,1);spin_unlock(&b->lock);
  if(!ok)return dropped(7);
 }
 if(cfg->icmp_ip_pps){
  u64 *slot=lookup(&echo_rates,src);
  if(!slot){u64 empty=0;update(&echo_rates,src,&empty,1);slot=lookup(&echo_rates,src);if(!slot)return dropped(7);}
  // LRU maps cannot contain spin locks. GCRA uses one atomic virtual arrival
  // timestamp; interval rounding is conservative (at most one nanosecond).
  u64 interval=(1000000000ULL+(u64)cfg->icmp_ip_pps-1)/(u64)cfg->icmp_ip_pps;
  u64 cap=now+(u64)cfg->icmp_ip_burst*interval;
  int ok=0;
  #pragma unroll
  for(int i=0;i<8;i++){
   u64 old=*slot;u64 start=old>now?old:now;u64 next=start+interval;
   if(next>cap)break;
   if(__sync_val_compare_and_swap(slot,old,next)==old){ok=1;break;}
  }
  if(!ok)return dropped(7);
 }
 return passed();
}
INLINE int decide(struct source *src,const u8 *l4,const u8 *end,u8 protocol,struct limits *cfg,u32 length,u32 broken,u32 available){
 if(l4+4>end||available<4)return unparsed();
 u32 port_key=((u32)protocol<<16)|read16(l4+2);
 if(!lookup(&ports,&port_key))return passed();
 if(allowed(src))return passed();
 if(cfg&&cfg->invalid_lengths){
  if(broken)return dropped(8);
  if(protocol==6){if(l4+20>end||available<20)return dropped(8);u32 size=(l4[12]>>4)*4;if(size<20||size>available||l4+size>end)return dropped(8);}
  else {if(l4+8>end||available<8)return dropped(8);u32 size=read16(l4+4);if(size<8||size>available)return dropped(8);}
 }
 u32 syn=0;
 if(protocol==6){
  if(l4+20>end||available<20)return unparsed();
  u8 flags=l4[13];
  if(cfg&&cfg->invalid_flags&&(flags&2)&&(flags&5))return dropped(8);
  syn=(flags&0x12)==0x02;
 }
 u32 *blocked=0;
 if(src->family==4){struct prefix4 key={.bits=32};__builtin_memcpy(key.addr,src->addr,4);blocked=lookup(&block4,&key);}
 else{struct prefix6 key={.bits=128};__builtin_memcpy(key.addr,src->addr,16);blocked=lookup(&block6,&key);}
 if(blocked)return dropped(2);
 if(!cfg)return passed();
 u64 now=ktime_ns();
 if(cfg->temporary_blocks){u64 *until=lookup(&temporary_bans,src);if(until&&*until>now)return dropped(9);}
 if(!global_budget(cfg,length,syn,now))return dropped(6);
 if(!cfg->packets_per_sec&&!cfg->syns_per_sec)return passed();
 struct budget *budget=lookup(&rates,src);
 if(!budget){struct budget empty={};update(&rates,src,&empty,1);budget=lookup(&rates,src);if(!budget)return dropped(3);}
 u32 second=(u32)(now/1000000000ULL);
 if(!consume(&budget->packets,second,cfg->packets_per_sec))return dropped(3);
 if(syn&&!consume(&budget->syns,second,cfg->syns_per_sec))return dropped(3);
 return passed();
}
SEC("xdp") int fess_filter(struct xdp_md *ctx){
 const u8 *data=(void *)(unsigned long)ctx->data;
 const u8 *end=(void *)(unsigned long)ctx->data_end;
 count(0);
 if(data+14>end)return unparsed();
 u16 ethertype=read16(data+12);u32 offset=14;
 #pragma unroll
 for(int i=0;i<2;i++){if(ethertype==0x8100||ethertype==0x88a8){if(data+offset+4>end)return unparsed();ethertype=read16(data+offset+2);offset+=4;}}
 u32 zero=0;struct limits *cfg=lookup(&config,&zero);
 struct source src={};u8 protocol=0;u32 broken=0,length=(u32)(end-data),ip_end=length;
 if(ethertype==0x0800){
  const u8 *ip=data+offset;if(ip+20>end)return unparsed();
  u32 ihl=(ip[0]&15)*4;if((ip[0]>>4)!=4||ihl<20||ip+ihl>end)return unparsed();
  src.family=4;__builtin_memcpy(src.addr,ip+12,4);protocol=ip[9];
  if(read16(ip+6)&0x3fff){if(cfg&&cfg->drop_fragments)return dropped(4);return passed();}
  u32 total=read16(ip+2);if(total<ihl||ip+total>end)broken=1;else ip_end=offset+total;
  offset+=ihl;
 }else if(ethertype==0x86dd){
  const u8 *ip=data+offset;if(ip+40>end||(ip[0]>>4)!=6)return unparsed();
  src.family=6;__builtin_memcpy(src.addr,ip+8,16);protocol=ip[6];
  u32 payload=read16(ip+4);
  // Jumbograms require separate option parsing; leave them to Linux.
  if(!payload)return unparsed();
  if(ip+40+payload>end)broken=1;else ip_end=offset+40+payload;
  offset+=40;
  #pragma unroll
  for(int i=0;i<6;i++){
   if(protocol==0||protocol==43||protocol==60||protocol==51){
    const u8 *ext=data+offset;if(ext+2>end||offset+2>ip_end)return unparsed();
    u32 size=protocol==51?((u32)ext[1]+2)*4:((u32)ext[1]+1)*8;
    if(size<8||ext+size>end||offset+size>ip_end)return unparsed();protocol=ext[0];offset+=size;
   }else if(protocol==44){
    const u8 *frag=data+offset;if(frag+8>end||offset+8>ip_end)return unparsed();
    if(read16(frag+2)&0xfff9){if(cfg&&cfg->drop_fragments)return dropped(4);return passed();}
    protocol=frag[0];offset+=8;
   }
  }
 }else{return passed();}
 if(offset>ip_end)return unparsed();
 if((src.family==4&&protocol==1)||(src.family==6&&protocol==58))return echo(&src,data+offset,end,cfg,ip_end-offset);
 if(protocol!=6&&protocol!=17)return passed();
 return decide(&src,data+offset,end,protocol,cfg,length,broken,ip_end-offset);
}
char _license[] SEC("license")="Apache-2.0";
