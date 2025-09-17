#ifndef __KSU_H_THRONE_TRACKER
#define __KSU_H_THRONE_TRACKER

void ksu_throne_tracker_init(void);

void ksu_throne_tracker_exit(void);

void track_throne(void);

#include "ksu.h"

int ksu_update_uid_list(struct uid_list_data *uid_data);

#endif
