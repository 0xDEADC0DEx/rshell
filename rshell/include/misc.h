#ifndef MISC_H
#define MISC_H

#define DEBUG

#ifdef DEBUG
#define dbprintf(f, p...) printf(f, p)
#define dbprint(f) printf(f)
#else
#define dbprintf(f, p...) ((void)0)
#define dbprint(f) ((void)0)
#endif


int forkoff();
int closepipe(int pipe[2]);

#endif
