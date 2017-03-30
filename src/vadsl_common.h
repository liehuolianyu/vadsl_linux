
extern char *p_name;

void time_print(FILE *stream, char *str);
void name_print(FILE *stream);
void error_print_nolock(char *str, bool use_errno);
void info_print_nolock(char *str);
