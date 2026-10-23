package xdpguard

// CounterNames follows the stable counter indexes in filter.c.
var CounterNames = []string{"seen", "passed", "cidr_drop", "rate_drop", "fragment_drop", "malformed_pass", "global_budget_drop", "icmp_ping_drop", "malformed_drop", "temporary_block_drop"}
