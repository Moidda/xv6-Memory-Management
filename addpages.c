#include "types.h"
#include "stat.h"
#include "user.h"

int stdout = 2;

int main(int argc, char *argv[]) {

	void *m;
	int pid;

	pid = getpid();
	printf(stdout, "pid = %d\n", pid);
	int bytes = atoi(argv[1]);

	m = malloc(1024*bytes);	
	
	sleep(500);
	
	printf(stdout, "Done");

	exit();
}
