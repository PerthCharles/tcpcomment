#ifndef __ASM_CRIS_BARRIER_H
#define __ASM_CRIS_BARRIER_H

#define nop() __asm__ __volatile__ ("nop");

/* __asm__          用于指示编译器这里插入汇编代码
 * __volatile__     告诉编译器严禁对该语句进行优化，即GCC中的volatile关键字的含义
 * "": : :          表示具体的汇编指令为空，output也为空，input也为空
 * "memory"         语法中，此域用于告诉编译器当前汇编语句可能修改哪些内存/寄存器，
 *                  使用memory就是告诉编译器，之后进行内存访问时必须假设所有内存已经被修改过，
 *                  不得使用寄存器中缓存的数据了
 * 所以这条barrier()语句的作用就是：
 *      将所有寄存器缓存的数据刷新到memory中去
 * 从而保证了在该语句之后的访问，都能访问到最新的数据状态。
 */
#define barrier() __asm__ __volatile__("": : :"memory")
#define mb() barrier()
#define rmb() mb()
#define wmb() mb()
#define read_barrier_depends() do { } while(0)
#define set_mb(var, value)  do { var = value; mb(); } while (0)

#ifdef CONFIG_SMP
#define smp_mb()        mb()
#define smp_rmb()       rmb()
#define smp_wmb()       wmb()
#define smp_read_barrier_depends()     read_barrier_depends()
#else
#define smp_mb()        barrier()
#define smp_rmb()       barrier()
#define smp_wmb()       barrier()
#define smp_read_barrier_depends()     do { } while(0)
#endif

#endif /* __ASM_CRIS_BARRIER_H */
