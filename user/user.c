#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>



int call_the_syscall(long int x){
	if(x == 174 || x == 177 ){
		printf("calling syscall %d\n",x);
		return syscall(x, "Th15_I5_4_t3s7_p4s5W0rd", "/home/manenti_0333574/Scaricati");
	}
	return syscall(x);
}

void* do_job(void * arg){
	int res;
	res = call_the_syscall((long int)arg);
	printf("sys call %ld returned value %d\n",(long int)arg,res);
	return NULL;
}

int main(int argc, char** argv){
	
	long int num_threads, arg;	
	pthread_t tid;
	int i;

	if(argc < 3){
		printf("usage: prog num-spawns sycall-num\n");
		return EXIT_FAILURE;
	}
	
	
	num_threads = strtol(argv[1],NULL,10);
	arg = strtol(argv[2],NULL,10);
	

	for (i=0; i<num_threads; i++){
		pthread_create(&tid,NULL,do_job,(void*)arg);
	}

	pause();

}