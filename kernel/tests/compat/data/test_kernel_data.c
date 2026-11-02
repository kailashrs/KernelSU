#include "api.h"
#include <assert.h>
#include <stdio.h>
#include "infra/kernel_data.h"
#include "infra/kernel_data_selinux.h"
static struct selinux_state state;
static struct lsm_blob_sizes blobs={0,0,16};
static struct proc_ns_operations ops;
static unsigned missing,misaligned,calls;
unsigned long find_kernel_symbol_exact(const char *name){
 unsigned bit;void *p;
 if(!strcmp(name,"selinux_state")){bit=1;p=&state;}
 else if(!strcmp(name,"selinux_blob_sizes")){bit=2;p=&blobs;}
 else {assert(!strcmp(name,"mntns_operations"));bit=4;p=&ops;}
 calls++;
 return (missing&bit)?0:(unsigned long)p+!!(misaligned&bit);
}
#include "../../../infra/kernel_data.c"
static void reset(void){missing=misaligned=calls=0;blobs.lbs_cred=0;blobs.lbs_inode=16;memset(&ksu_kernel_data,0,sizeof(ksu_kernel_data));}
static void unpublished(void){assert(!ksu_kernel_data.selinux && !ksu_kernel_data.blobs && !ksu_kernel_data.mntns);}
int main(void){
 for(unsigned mask=1;mask<8;mask++){reset();missing=mask;assert(ksu_kernel_data_init()==-ENOENT);assert(calls==3);unpublished();}
 for(unsigned mask=1;mask<8;mask++){reset();misaligned=mask;assert(ksu_kernel_data_init()==-EINVAL);unpublished();}
 reset();blobs.lbs_cred=-1;assert(ksu_kernel_data_init()==-EINVAL);unpublished();
 reset();blobs.lbs_inode=PAGE_SIZE;assert(ksu_kernel_data_init()==-EINVAL);unpublished();
 reset();blobs.lbs_cred=PAGE_SIZE;assert(ksu_kernel_data_init()==-EINVAL);unpublished();
 reset();blobs.lbs_inode=-1;assert(ksu_kernel_data_init()==-EINVAL);unpublished();
 reset();assert(!ksu_kernel_data_init());assert(ksu_kernel_selinux_state()==&state);assert(ksu_kernel_blob_sizes()==&blobs);assert(ksu_kernel_mntns_ops()==&ops);
 char storage[128]={0};struct cred c={storage};struct inode i={storage},nil={0};
 assert((void*)ksu_selinux_cred(&c)==storage);assert((void*)ksu_selinux_inode(&i)==storage+16);assert(!ksu_selinux_inode(&nil));
 blobs.lbs_cred=8;blobs.lbs_inode=24;
 assert((void*)ksu_selinux_cred(&c)==storage+8);assert((void*)ksu_selinux_inode(&i)==storage+24);
 struct ksu_kernel_data saved=ksu_kernel_data;missing=1;assert(ksu_kernel_data_init()==-ENOENT);assert(!memcmp(&saved,&ksu_kernel_data,sizeof(saved)));
 puts("PASS: all missing/misaligned combinations fail before publication; blob bounds checked; live typed offsets and inode NULL behavior preserved");
}
