#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sqlite3.h>

#define DEBUG 0		// global debug flag - set to 1 to print (a LOT of) extra information

int status;
static int prog_update = 0;	// flag used by interrupts to signal progress update
static int p_start = 1, p_end = 1023, verbose = 0, file = 0;	//some default arguments
static char *ip;

struct addrinfo params, *servinfo;

//database variables
int rc, db_ok = 1;
sqlite3 *db;
sqlite3_stmt *res;
char *err_msg;

FILE *fp;

char *append(char*,char*); 	//appends two strings.
char *toStr(int);	//converts an integer to a string (for port specification)
char *portInfo(int);	//gets the/a service associated with a port
int length(char*);	//works out length of string (because why use a standard library function?)
char *writeXML(char*,int,char*,int);	//reformats the input into xml-like syntax.
int parse(char*, int);	//parses the port string given in cmd args to a start or end port (based on int passed) 
void sighandle(int);	//handle the interrupt to give progress report.
void exithandle(int);	//handle a Ctrl+C (mostly important for clean file I/O)
void usage(void);	//print invalid usage message and quit
void help(char*);	//print help message
void procArgs(int,char**);	//process input arguments
void showBanner(void);	//shows the port scan banner
int *checkOpen(int);	//check if a port is open.

int main(int argc, char **argv){

	rc = sqlite3_open("services.db", &db);
	if(rc != SQLITE_OK){
		printf("error opening services database. check it is there. port service resolution may be affected.\n");
		db_ok = 0;
	}

	//assign interrupt handler
	signal(SIGUSR1, sighandle);
	signal(SIGQUIT, sighandle);
	signal(SIGINT, exithandle);

	//set default IP address.
	ip = malloc(15 * sizeof(char));
	ip = "127.0.0.1";

	if(argc<2) printf("Usage: %s {-h | {-t <ip> | -d <domain name>} -r <range> -v -f}\n"
				"Proceeding with default values 127.0.0.1 1-1023\n", argv[0]);
	else if(argv[1][0] == '-' && argv[1][1] == 'h') {
			help(argv[0]);
			return 0;
	}
	else procArgs(argc, argv);

	if(DEBUG) printf("[debug] past procArgs\n");

	if(file == 1){
		fp = fopen(append(ip, ".xml"), "w");
		if(fp == NULL) {
			printf("logging not available (file error).\n");
			file=0;
		}

		fprintf(fp, "<xml version=\"1.0\"?>\n");
		fprintf(fp, "\t<portscan>\n");
		fprintf(fp, "\t\t<options>\n");
		fprintf(fp, "%s", writeXML("ip", 3, ip, 1));
		fprintf(fp, "%s", writeXML("start_port", 3, toStr(p_start), 1));
		fprintf(fp, "%s", writeXML("end_port", 3, toStr(p_end), 1));
		fprintf(fp, "\t\t</options>\n");
	}

	if(DEBUG) printf("[debug] past file_init\n");

	//set connect type information.
	memset(&params, 0, sizeof params);
	params.ai_family = AF_UNSPEC;
	params.ai_socktype = SOCK_STREAM;

	showBanner();

	time_t current_time = time(NULL);
	char f_t[50];
	strftime(f_t, 50, "%c", localtime(&current_time));
	printf("Time started: %s\n", f_t);

	if(file){
		fprintf(fp, "%s", writeXML("starttime", 2, f_t, 0));
	}

	printf("-----------------------------------------\n");
	printf("Port\tStatus\tProtocol\tService\n");
	printf("-----------------------------------------\n");

	if(file){
		fprintf(fp, "\t\t<ports>\n");
	}

	//scan each specified port
	int tot = 0;
	int i = p_start;
	char na_string[4] = "N/A";
	do {
		if(prog_update){
			printf("Progress report - on port %d (%d ports scanned).\n", i, tot);
			prog_update = 0;
		}

		int *t = checkOpen(i);
		int s = t[0];
		int r = t[1];
		char *p_info = na_string;

		if(verbose){
			p_info = (r==-1?na_string:portInfo(i));
			printf("%d\t%s\t%s\t\t%s\n", i, (r==-1?"closed":"open"), 
				(servinfo->ai_protocol == 6 ? "tcp":(servinfo->ai_protocol == 17?"udp":"unknown")), 
				p_info);

			if(file){
				fprintf(fp, "\t\t\t<port>\n");
				fprintf(fp, "%s", writeXML("id", 4, toStr(i), 0) );
				fprintf(fp, "%s", writeXML("status", 4, r==-1?"closed":"open", 0) );
				fprintf(fp, "%s", writeXML("protocol", 4, servinfo->ai_protocol == 17?"udp":(servinfo->ai_protocol==6?"tcp":"unknown"), 0));
				fprintf(fp, "%s", writeXML("service", 4, p_info, 0));
				fprintf(fp, "\t\t\t</port>\n");
			}
		}
		else if(r==0) {
			p_info = portInfo(i);
			printf("%d\t%s\t%s\t\t%s\n",i, "open",
				(servinfo->ai_protocol == 6 ? "tcp":(servinfo->ai_protocol == 17?"udp":"unknown")), 
				p_info );
			if(file){
				fprintf(fp, "\t\t\t<port>\n");
				fprintf(fp, "%s", writeXML("id", 4, toStr(i), 0) );
				fprintf(fp, "%s", writeXML("status", 4, "Open", 0) );
				fprintf(fp, "%s", writeXML("protocol", 4, servinfo->ai_protocol == 17?"udp":(servinfo->ai_protocol==6?"tcp":"unknown"), 0));
				fprintf(fp, "%s", writeXML("service", 4, p_info, 0));
				fprintf(fp, "\t\t\t</port>\n");
			}
		}

		close(s);	//close the socket
		tot++;
		i++;
	} while (i<p_end);	//do while to allow specifying individual port like -r 80-
	if(file) fprintf(fp, "\t\t</ports>\n");

	printf("========================================\n");
	time_t end_time = time(NULL);
	printf("Time end: %s", ctime(&end_time));

	int time_dif = (int)difftime(end_time, current_time);

	printf("Time taken: %d mins %d secs\n", time_dif/60, time_dif%60);
	if(file) {
		char e_t[50];
		strftime(e_t, 50, "%c", localtime(&end_time));
		fprintf(fp, "%s", writeXML("endtime", 2, e_t, 0));
		fprintf(fp, "\t</portscan>\n");
		fclose(fp);
	}

	return 0;
}

//prints the standard incorrect argument message and exits.
void usage(void){
	printf("incorrect argument presentation. consult help (-h).\n");
	exit(0);
}

void help(char *progName){
	printf("Usage: %s {-h | {-t <ip> | -d <domain name>} -r <range> -v -f}\n", progName);
	printf("\t-h : help menu\n"
		"\t-t : target IP address\n"
		"\t-d : domain name (WITHOUT http(s)://)\n"
		"\t-r : port range (e.g. 1-1024)\n"
		"\t-v : verbose (print closed ports too)\n"
		"\t-f : output to file\n");
	printf("Use SIGQUIT (Ctrl+\\) or SIGUSR1 (kill -USR1 $(pgrep a.out) ) to get a progress update.\n");
}

void procArgs(int argc, char **argv){
	for(int i = 1; i < argc; i++){
		if(DEBUG) printf("parsing arg %s\n", argv[i]);
		if(argv[i][0] == '-'){
			switch(argv[i][1]){
				case 't' : if(i+1 >= argc) usage();
					ip = argv[i+1];
					break;
				case 'd' : if(i+1 >= argc) usage();
					ip = argv[i+1];
					break;
				case 'r' : if(i+1 >= argc) usage();
					p_start = parse(argv[i+1], 0);
					p_end = parse(argv[i+1], 1);
					break;
				case 'v' : verbose = 1;
					break;
				case 'f' : file = 1;
					break;
				default: printf("unknown argument. consult help.\n");
					exit(0);
			}
		}
	}
}

char *writeXML(char *containerName, int indent, char *value, int newLineSep){
	if(DEBUG) printf("[debug] in writeXML [%s,%d,%s,%d]\n",containerName,indent,value,newLineSep);
	char *str = malloc(sizeof(char));
	char *ind = malloc(sizeof(char));
	
	for(int i = 0; i < indent; i++){
		ind = append(ind, "\t");
	}

	if(DEBUG) printf("1");	

	str=append(str, ind);
	str = append(str, "<");
	str = append(str, containerName);
	str = append(str, ">");

	if(DEBUG) printf("2");

	if(newLineSep) {
		str = append(str, "\n");
	}
	
	str = append(str, newLineSep?append(ind, "\t"):"");
	str = append(str, value);
	if(newLineSep) {
		str = append(str, "\n");
	}

	if(DEBUG) printf("3");

	if(newLineSep) {
		str = append(str,ind);
	}
	str = append(str, "</");
	str = append(str, containerName);
	str = append(str, ">");
	str = append(str, "\n");

	if(DEBUG) printf("4\n");

	return str;
	
}

void showBanner(void){
	printf("================\n");
	printf("PortScanner v1.0\n");
	printf("================\n");

	printf("Host selected: %s\n", ip);
	printf("Port range: %d-%d\n", p_start, p_end);
}

int *checkOpen(int port){
	status = getaddrinfo(ip, toStr(port), &params, &servinfo);	//resolve the information
	int s = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);	//open a socket
	int *t = malloc(sizeof(int) * 2);
	t[0] = s;
	t[1] = connect(s, servinfo->ai_addr, servinfo->ai_addrlen);	//attempt to connect
	return t;

}

char *append(char *a, char *b){

	int a_len = length(a);
	int b_len = length(b);

	char *c = malloc(sizeof(char) * a_len+b_len+1);

	for(int i = 0; i < a_len; i++){
		c[i] = a[i];
	}

	for(int i = a_len; i < a_len+b_len; i++){
		c[i] = b[i - a_len];
	}
	c[a_len + b_len] = '\0';
	return c;
}

void check(int code, char *str){
	if(code != SQLITE_OK) printf("\n\nerror in %s\n", str);
}


char *portInfo(int port){
	if(!db_ok) {
		return "unknown (db_fail)";
	}

	char *sql = append("SELECT Service FROM Assignments WHERE Port = '", append(toStr(port), "';") );

	sqlite3_prepare_v2(db, sql, length(sql), &res, 0);
	check(rc, "prepare");

	while( (rc = sqlite3_step(res)) == SQLITE_ROW){
		char *service_name = (char*)sqlite3_column_text(res, 0);
		return service_name;
	}

	return "unknown (db_empty)";
}

//converts an integer to string.
char *toStr(int x){
	int size = 1, d = x;
	while(d != 0){
		size++;
		d/=10;
	}
	size--;

	char *str = malloc(sizeof(char) * size);
	for(int i = 1; i <= size; i++){
		str[size - i] = x%10 + '0';
		x /= 10;
	}
	str[size] = '\0';
	return str;
}

//parse the argument supplied to -r (if pt is 0 it resolves the start port, if pt is 1 it resolves the end port).
int parse(char *str, int pt){
	int sum = 0, weight = 1, start = 0, dash_idx = 0;
	while(str[dash_idx] != '-') dash_idx++;

	if(pt == 1){
		weight = pow(10, (length(str) - dash_idx)-2);
		start = dash_idx + 1;
	}
	else{
		weight = pow(10, dash_idx - 1);
	}

	for(int i = start; i < length(str); i++){
		if(str[i] == '-' || str[i] == '\0') return sum;
		sum += (str[i] - '0') * weight;
		weight /= 10;
	}
	return sum;
}

void sighandle(int signum){
	prog_update = 1;	
}

void exithandle(int signum){
	time_t end_time = time(NULL);

	if(file) {
		char e_t[50];
		strftime(e_t, 50, "%c", localtime(&end_time));
		fprintf(fp, "%s", writeXML("endtime", 2, e_t, 0));
		fprintf(fp, "\t</portscan>\n");
		fclose(fp);
	}
	exit(0);
}

int length(char *a){
	int len = 0;
	while(a[len] != 0) len++;
	return len;
}
