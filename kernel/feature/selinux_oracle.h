#ifndef __KSU_H_SELINUX_ORACLE
#define __KSU_H_SELINUX_ORACLE

#ifdef CONFIG_KSU_HIDE_SELINUX_ORACLE
void ksu_selinux_oracle_init(void);
void ksu_selinux_oracle_exit(void);
#else
static inline void ksu_selinux_oracle_init(void) { }
static inline void ksu_selinux_oracle_exit(void) { }
#endif

#endif
