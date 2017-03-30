
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "vadsl_common.h"

void time_print(FILE *stream, char *str){
	time_t time_std;
	struct tm *time_str;

	time(&time_std);
	time_str = localtime(&time_std);
	fprintf(stream, "%s%.2dh%.2dm%.2ds\n", str, time_str->tm_hour, time_str->tm_min, time_str->tm_sec);
}

void name_print(FILE *stream){
	time_t time_std;
	struct tm *time_str;

	time(&time_std);
	time_str = localtime(&time_std);

	fprintf(stream, "%.2d-%.2d-%.2d:%s: ", time_str->tm_hour, time_str->tm_min, time_str->tm_sec, p_name);
}

void error_print_nolock(char *str, bool use_errno){
	name_print(stderr);
	fprintf(stderr, "ERROR:");
	if(use_errno)
		perror(str);
	else
		fprintf(stderr, "%s\n",str);
	fflush(stderr);
}

void info_print_nolock(char *str){
	name_print(stderr);
	fprintf(stderr, "INFO:%s\n",str);
	fflush(stderr);
}
