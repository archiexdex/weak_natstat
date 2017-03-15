#include <bits/stdc++.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex>
using namespace std;


const string tcpPath  = "/proc/net/tcp";
const string udpPath  = "/proc/net/udp";
const string tcp6Path = "/proc/net/tcp6";
const string udp6Path = "/proc/net/udp6";

const char short_option[100] = "tu";
const struct option long_option[] {
	{"tcp", 0, NULL, 't'},
	{"udp", 0, NULL, 'u'},
	{NULL,  0, NULL, 0  }
};
struct node {
	string local, rem;
	int inode;
	node(const char _local[1000], const char _rem[1000], int _inode ) : 
		local(_local), rem(_rem), inode(_inode) { }
};
char buf[10000];
map<int,string> XD;

string getAddr(char a[1000]) {
	char b[100];
	string tmp = "";
	string addr = "";
	//Get IP address
	for( int i = 3 ; i >= 0 ; --i ){
		tmp = "";
		tmp += a[i*2];
		tmp += a[i*2+1];
		tmp = to_string(stoi(tmp,nullptr,16) );
		if (i) addr += tmp + ".";
		else addr += tmp + ":";
	}
	//Get port
	tmp = "";
	for( int i = 9; i < strlen(a) ; ++i )
		tmp += a[i];
	int port = stoi(tmp,nullptr,16);
	if (!port) addr += "*";
	else {
		addr += to_string(port);
	}
	return addr;
}

string getipv6(char a[1000]){
	
	int ip[10], tag[10];
	//Modify position
	for(int i = 0; i < 32 ; i += 8){
		swap(a[i]  ,a[i+6]);
		swap(a[i+1],a[i+7]);
		swap(a[i+2],a[i+4]);
		swap(a[i+3],a[i+5]);
	}
	//Tranform 16 to 10
	memset(ip,-1,sizeof(ip) );
	memset(tag,0,sizeof(tag) );
	for( int i = 0 ; i < 8 ; ++i ){
		string tmp = "";
		tmp += a[i*4]; 
		tmp += a[i*4+1];
		tmp += a[i*4+2];
		tmp += a[i*4+3];
		ip[i] = stoi(tmp,nullptr,16);
	}
	for( int i = 1 ; i <= 8 ; i++ ){
		if( ip[i-1] == 0 )
			for( ; i <= 8 ; ++i )
				if( ip[i-1] == 0 )
					tag[i] = tag[i-1] + 1;
				else break;
	}
	int st = 0 , ed = 0, max = -1234567;
	for( int i = 1 ; i <= 8 ; ++i )
		if(tag[i] > max) max = tag[i], ed = i-1;
	for( int i = ed ; i > 0 ; --i )
		if( !tag[i] ){
			st = i;
			break;
		}
	string ret = "";
	bool flg = false;
	for( int i = 0 ; i < 8 ; ++i ){
		if( st <= i && i <= ed ){
			if(flg == false){
				flg = true;
				ret += "::";
			}
			continue;
		}
		if (!i) {
			sprintf(buf,"%x",ip[i]);
			ret += buf;
			continue;
		}
		if (ret.back() != ':') ret += ':';
		sprintf(buf,"%x",ip[i]);
		ret += buf;
	}
	ret += ":";
	string tmp = "";
	for( int i = 33; i < strlen(a) ; ++i)
		tmp += a[i];
	int port = stoi(tmp,nullptr,16);
	if(!port) ret += "*";
	else ret += to_string(port);
	return ret;
}

vector<string> getPath(string s) {
	DIR *dirp;
	dirent *direntp;
	vector<string> vec;
	if ( s.back() != '/' ) s += '/';
	dirp = opendir(s.c_str() );
	if( !dirp ) return vec;
	while( (direntp = readdir(dirp) ) != NULL ){
		if ( !strcmp(direntp->d_name,".") || !strcmp(direntp->d_name,"..") )
			continue;
		vec.push_back(s+direntp->d_name);
	}
	closedir(dirp);
	return vec;
}

vector<string> getfd() {
	vector<string> files = getPath("/proc/");
	vector<string> fds;
	for(auto dir: files) {
		vector<string> tmp = getPath(dir + "/fd/");
		fds.insert(fds.end(), tmp.begin(), tmp.end() );
	}
	return fds;
}

string get_cmd(string pid) {
	fstream fp;
	string path = "/proc/";
	path += pid + "/cmdline";
	fp.open(path.c_str(),ios::in);
	fp.getline(buf,1024);
	fp.close();
	return pid+"/"+buf;
}

vector<node> parser(string path, int type) {
	fstream fp;
	char local[1000], rem[1000], inode[1000];
	vector<node> vec;
	
	fp.open(path.c_str(), ios::in);
	fp.getline(buf,1024);
	while( !fp.eof() ){
		fp.getline(buf,1024);
		if ( !strlen(buf) ) break;
		
		sscanf(buf,"%*s %s %s %*s %*s %*s %*s %*s %*s %s",local, rem, inode);
		if (type == 4){
			node tmp(getAddr(local).c_str(),getAddr(rem).c_str(),stoi(inode,nullptr,10) );
			vec.push_back(tmp);
		}
		else if( type == 6 ){
			node tmp(getipv6(local).c_str(),getipv6(rem).c_str(),stoi(inode,nullptr,10) );
			vec.push_back(tmp);
		}
	}
	fp.close();
	return vec;
}

void show_tcp(string sf) {
	printf("List of TCP connections:\n");
	printf("Proto Local Address           Foreign Address         PID/Program name and arguments\n");
	smatch m;
	regex reg(sf.c_str());
	auto t4 = parser(tcpPath, 4);
	for(auto ptr : t4) {
		string ino = XD[ptr.inode];
		if ( ino == "" ) ino = "-";
		sprintf(buf,"%s %s %s",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
		string tmp = buf;
		if( regex_search(tmp,m,reg) )
			printf("%-5s %-23s %-23s %-23s\n","tcp",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
	}
	auto t6 = parser(tcp6Path, 6);
	for(auto ptr : t6) {
		string ino = XD[ptr.inode];
		if ( ino == "" ) ino = "-";
		sprintf(buf,"%s %s %s",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
		string tmp = buf;
		if( regex_search(tmp,m,reg) )
			printf("%-5s %-23s %-23s %-23s\n","tcp6",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
	}
}

void show_udp(string sf) {
	printf("List of UDP connections:\n");
	printf("Proto Local Address           Foreign Address         PID/Program name and arguments\n");
	smatch m;
	regex reg(sf.c_str() );
	auto t4 = parser(udpPath, 4);
	for(auto ptr : t4) {
		string ino = XD[ptr.inode];
		if ( ino == "" ) ino = "-";
		sprintf(buf,"%s %s %s",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str() );
		string tmp = buf;
		if( regex_search(tmp,m,reg) )
			printf("%-5s %-23s %-23s %-23s\n","udp",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
	}
	auto t6 = parser(udp6Path, 6);
	for(auto ptr : t6) {
		string ino = XD[ptr.inode];
		if ( ino == "" ) ino = "-";
		sprintf(buf,"%s %s %s",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
		string tmp = buf;
		if( regex_search(tmp,m,reg) )
			printf("%-5s %-23s %-23s %-23s\n","udp6",ptr.local.c_str(),ptr.rem.c_str(),ino.c_str());
	}
	
}

int main(int argc, char* argv[]) {
	
	bool ist = true , isu = true, istt = false, isuu = false;
	vector<node> Vec;
	int opt;
	while ( (opt = getopt_long(argc, argv, short_option, long_option, NULL) ) != -1 ){
		switch(opt) {
			case 't':
				istt = true;
				break;
			case 'u':
				isuu = true;
				break;
			default :
				puts("oops! The option is not accepted!");
		};
	}
	if(istt || isuu){
		ist = istt , isu = isuu;
	}
	string sf = "";
	if( argc > optind )
		sf = argv[optind];
	//cout << optind << sf << argc << endl;
	//Build inode to pid
	vector<string> fds;
	fds = getfd();
	struct stat stat_buf;
	
	for( auto ptr : fds ){
		stat(ptr.c_str(), &stat_buf);
		
		if( S_ISSOCK(stat_buf.st_mode) ){
			int st , ed, ct = 0;
			for( int i = 0 ; i < ptr.size() ; ++i ){
				if(ptr[i] == '/')  ++ct;
				if(ct == 1) st = i;
				else if(ct == 2) ed = i;
			}
			string pid = ptr.substr(st+2,ed-st-1);
			//readlink(ptr.c_str(),buf,sizeof(buf) );
			XD[stat_buf.st_ino] = get_cmd(pid) ;
			///printf(">>%d %s<<\n",stat_buf.st_ino,get_cmd(pid).c_str() );
		}
	}
	if( ist ){
		show_tcp(sf);
		putchar('\n');
	}
	if( isu ){
		show_udp(sf);
		putchar('\n');
	}
	
	return 0;
}
