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
struct prefix4 {u32 bits; u8 addr[4];};
struct prefix6 {u32 bits; u8 addr[16];};
struct source {u32 family; u8 addr[16];};
struct limits {u32 packets_per_sec;u32 syns_per_sec;u32 drop_fragments;};
struct budget {u64 packets;u64 syns;};
#define TRIE(name, keytype) struct {__uint(type,11);__uint(max_entries,16384);__uint(map_flags,1);__type(key,keytype);__type(value,u32);} name SEC(".maps")
TRIE(block4,struct prefix4); TRIE(block6,struct prefix6);
TRIE(allow4,struct prefix4); TRIE(allow6,struct prefix6);
struct {__uint(type,1);__uint(max_entries,4096);__type(key,u32);__type(value,u32);} ports SEC(".maps");
struct {__uint(type,2);__uint(max_entries,1);__type(key,u32);__type(value,struct limits);} config SEC(".maps");
struct {__uint(type,9);__uint(max_entries,65536);__type(key,struct source);__type(value,struct budget);} rates SEC(".maps");
struct {__uint(type,6);__uint(max_entries,6);__type(key,u32);__type(value,u64);} counters SEC(".maps");
INLINE void count(u32 key){u64 *v=lookup(&counters,&key);if(v)(*v)++;}
INLINE int passed(void){count(1);return PASS;}
INLINE int dropped(u32 reason){count(reason);return DROP;}
INLINE u16 read16(const u8 *p){return ((u16)p[0]<<8)|p[1];}
// High 32 bits are a monotonic second, low 32 bits the count in that window.
// CAS prevents lost increments across RX CPUs; contention exhaustion drops
// conservatively rather than allowing an unchecked packet.
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
INLINE int decide(struct source *src,const u8 *l4,const u8 *end,u8 protocol,struct limits *cfg){
 if(l4+4>end)return passed();
 u16 port=read16(l4+2);u32 port_key=((u32)protocol<<16)|port;
 if(!lookup(&ports,&port_key))return passed();
 u32 *allowed=0,*blocked=0;
 if(src->family==4){struct prefix4 key={.bits=32};__builtin_memcpy(key.addr,src->addr,4);allowed=lookup(&allow4,&key);blocked=lookup(&block4,&key);}
 else{struct prefix6 key={.bits=128};__builtin_memcpy(key.addr,src->addr,16);allowed=lookup(&allow6,&key);blocked=lookup(&block6,&key);}
 if(allowed)return passed();
 if(blocked)return dropped(2);
 if(!cfg || (!cfg->packets_per_sec&&!cfg->syns_per_sec))return passed();
 u32 syn=0;if(protocol==6){if(l4+20>end)return passed();syn=(l4[13]&0x12)==0x02;}
 struct budget *budget=lookup(&rates,src);
 if(!budget){struct budget empty={};update(&rates,src,&empty,1);budget=lookup(&rates,src);if(!budget)return dropped(3);}
 u32 now=(u32)(ktime_ns()/1000000000ULL);
 if(!consume(&budget->packets,now,cfg->packets_per_sec))return dropped(3);
 if(syn&&!consume(&budget->syns,now,cfg->syns_per_sec))return dropped(3);
 return passed();
}
SEC("xdp") int fess_filter(struct xdp_md *ctx){
 const u8 *data=(void *)(unsigned long)ctx->data;
 const u8 *end=(void *)(unsigned long)ctx->data_end;
 count(0);
 if(data+14>end){count(5);return passed();}
 u16 ethertype=read16(data+12);u32 offset=14;
 #pragma unroll
 for(int i=0;i<2;i++){if(ethertype==0x8100||ethertype==0x88a8){if(data+offset+4>end){count(5);return passed();}ethertype=read16(data+offset+2);offset+=4;}}
 u32 zero=0;struct limits *cfg=lookup(&config,&zero);
 struct source src={};u8 protocol=0;
 if(ethertype==0x0800){
  const u8 *ip=data+offset;if(ip+20>end){count(5);return passed();}
  u32 ihl=(ip[0]&15)*4;if((ip[0]>>4)!=4||ihl<20||ip+ihl>end){count(5);return passed();}
  src.family=4;__builtin_memcpy(src.addr,ip+12,4);protocol=ip[9];
  // Noninitial fragments have no transport header. Fragment dropping is an
  // explicit interface-wide option; default behavior leaves them to Linux.
  if(read16(ip+6)&0x3fff){if(cfg&&cfg->drop_fragments)return dropped(4);return passed();}
  offset+=ihl;
 }else if(ethertype==0x86dd){
  const u8 *ip=data+offset;if(ip+40>end||(ip[0]>>4)!=6){count(5);return passed();}
  src.family=6;__builtin_memcpy(src.addr,ip+8,16);protocol=ip[6];offset+=40;
  #pragma unroll
  for(int i=0;i<6;i++){
   if(protocol==0||protocol==43||protocol==60||protocol==51){
    const u8 *ext=data+offset;if(ext+2>end){count(5);return passed();}
    u32 size=protocol==51?((u32)ext[1]+2)*4:((u32)ext[1]+1)*8;
    if(size<8||ext+size>end){count(5);return passed();}protocol=ext[0];offset+=size;
   }else if(protocol==44){
    const u8 *frag=data+offset;if(frag+8>end){count(5);return passed();}
    if(read16(frag+2)&0xfff9){if(cfg&&cfg->drop_fragments)return dropped(4);return passed();}
    protocol=frag[0];offset+=8;
   }
  }
 }else{return passed();}
 if(protocol!=6&&protocol!=17)return passed();
 return decide(&src,data+offset,end,protocol,cfg);
}
char _license[] SEC("license")="Apache-2.0";
