#pragma once

#include "net.h"

extern struct net_device *ether_tap_init(const char *name, const char *addr);
