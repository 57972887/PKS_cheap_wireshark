#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CONSTANTS_FILE "Constants.txt"		//textovı súbor, kde sa nachádzajú konštanty resp. èísla jednotlivıch protokolov


struct Cmd {			// štruktúra pre zadávanie príkazov po spustení programu
	char path[80];			// premenná na uchovanie absolutnej cesty k .pcap súboru
	char filename[80];		// premenná na uchovanie absolutnej cesty k vıstpunému súboru
	char filter;			// premenná na uchovanie èísla protokolu, ktorı sa bude filtrova
	char redirect;			// premenná, ktorá slúi na presmerovanie vıstupu
};

struct List {		// štruktúra spájaného zoznamu, ktorá uchováva jednotlivé ip adresy a ich poèetnos v konkrétnom .pcap súbore
	unsigned int ip_address;	// 4 bajtové èíslo, ktoré oznaèuje ip adresu
	unsigned int count;		// príslušné èíslo k ip adrese, ktoré oznaèuje ko¾ko krát sa daná ip adresa v .pcap súbore nachádza
	struct List* next;		// smerník na ïalší záznam
};

void strfcat(char* source, char* format, ...) {		// funkcia, ktorá spája formátované stringy
	char buffer[2048];	
	va_list args;
	
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);
	
	strcat(source, buffer);
}

unsigned int convert_ip(char* string_ip) {		// funkcia konvertuje textovú formu ip adresy na èíselnú, aby sa mohla zapísa do spájaného zoznamu
	
	unsigned int result = 0;	// inicializácia vısledku na 0
	unsigned int temp_result = 0;	// inicializácia premnennej na 0
	short string_length = strlen(string_ip);	// inicializácia premennej, ktorá oznaèuje dåku stringu
	short offset  = 24;		// posun, ktorı sa bude pouíva pri konverzií ip adresy
	int i = 0;	// inicializácia pomocnej premennej
	
	while (i <= string_length) {	// vykonávaj cyklus pokial sa i nerovná dåke stringu
		if (string_ip[i] == '.' || i == string_length) {	// ak sa znak na pozicií i rovná bodke alebo sme na konci stringu tak vykonaj nasledujúce
			i++;	// inkrementuj premennú i
			result += (temp_result << offset);	// pripoèítaj k vısledku èiastkovı vısledok
			temp_result = 0; 	// nastav èiastkovı vısledok na 0
			offset -= 8;	// odpoèítaj od posunu èíslo 8
			continue;	// pokraèuj vo vykonávaní cyklu
		}
		temp_result *= 10;	// vynásob èiastkovı vısledok 10
		temp_result += string_ip[i] - 48;	// pripoèítaj k èiastkovému vısledku èíslo na pozícií i zo stringu
		i++;	// inkrementuj premennú i
	}
	
	return result;		// návratová hodnota je celá èíslo bez znamienka a predstavuje konvertovanú ip adresu
}

struct List* create_node(int ip_number) {	// funkcia vytvorí novı uzol resp. záznam do spájaného zoznamu
	struct List* node = (struct List*) malloc(sizeof(struct List));	// inicializácia premennej, alokácia poadovaného pamäového priestoru
	node->ip_address = ip_number;	// nastavenie premennej ip adresa
	node->count = 1;	// nastavenie premennej, ktorá oznaèuje vıskyt danej ip adresy na 1
	node->next = NULL;	// nastavenie smerníka na ïalší záznam na NULL
	return node;	// vrátenie uzla pre ïalšie spracovanie
}

struct List* add_ip_address_to_list(unsigned int ip_number, struct List* ip_list) {		// funkcia, ktorá pridá do sprajaného zoznamu poadovanú ip adresu, ak sa táto ip adresa u v spájanom zozname vyskytuje tak sa iba pripoèíta poèetnos
	if (ip_list == NULL) ip_list = create_node(ip_number);		// ak ešte štruktúra nebola inicializovaná, resp. neexistuje iadny záznam, tak vytvor prvı uzvol/záznam
	else {
		struct List* temp = ip_list;	// v opaènom prípade nastav premennú temp na zaèiatok zoznamu
		while (temp != NULL) {	// kım existujú záznamy v zozname tak prechádzaj jednotlivé záznamy
			if (ip_number == temp->ip_address) {	// ak sú ip adresy zhodné
				temp->count++;		// inkrementuj poèetnos ip adresy
				break;		// ukonèi cyklus
			}
			if (temp->next == NULL) {		// ak sme prešli všetky záznamy a nenastala zhoda v ip adresách, tak vytvor na konci novı uzol/záznam
				temp->next = create_node(ip_number);	// vytvorenie nového záznamu
				break;		// ukonèenie cyklu
			}
			else temp = temp->next;		// posun na ïalší záznam
		}
	}
	return ip_list;		// návratová hodnota je upravenı spájanı zoznam
}


int build_frame_length(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {	// funkcia zo štyroch bajtovıch èísel zostaví jedno èíslo
	int frame_length = 0;	// inicializácia ve¾kosti rámca
	int offset = 8;		// inicializácia premmenej posunu
	frame_length = a + (b << offset) + (c << offset*2) + (d << offset*3);	// vypoèítanie premennej, ktorá oznaèuje dåku rámca zostavenú zo štyroch bajtovıch èísel
	return frame_length;		// návratová hodnota oznaèuje vypoèítanú dåku rámca
}

unsigned char* cut_mac_address(int start, unsigned char* buffer) {		// funkcia, ktorá z buffera vystrihne mac adresu pod¾a premennej start
	unsigned char* result = (unsigned char*) malloc(6 * sizeof(unsigned char));		// inicializácia 6 bajtov pre uloenie mac adresy
	short i = 0;	// nastavenie pomocnej premennej pre cyklus
	for (i = 0; i < 6; i++) 
		result[i] = buffer[start+i];	// kopírovanie mac adresy do premennej result
	
	return result;	// návratová hodnota obsahuje prekopírovanú mac adresu z buffera
}

void print_hex(int number, char* line_buffer) {		// funkcia konvertuje decimálne èíslo na hexadecimálne, resp. vytlaèí miesto decimálneho èísla hexadecimálne
		switch(number) {
		case (10) :
			strfcat(line_buffer, "A");	// ak sa poadovaná èíslo rovná 10 vytlaè písmeno A
			break;
		case (11) :
			strfcat(line_buffer, "B");	// ak sa poadovaná èíslo rovná 11 vytlaè písmeno B
			break;
		case (12) :
			strfcat(line_buffer, "C");	// ak sa poadovaná èíslo rovná 12 vytlaè písmeno C
			break;
		case (13) :
			strfcat(line_buffer, "D");	// ak sa poadovaná èíslo rovná 13 vytlaè písmeno D
			break;
		case (14) :
			strfcat(line_buffer, "E");	// ak sa poadovaná èíslo rovná 14 vytlaè písmeno E
			break;
		case (15) :
			strfcat(line_buffer, "F");	// ak sa poadovaná èíslo rovná 15 vytlaè písmeno F
			break;
		default :
			strfcat(line_buffer, "%d", number);	// v opaènom prípade vytlaè zodpovedajúce èíslo
	}
}

void print_byte(unsigned char byte, const char symbol, char* line_buffer) {		// funkcia vytlaèí konkrétny bajt, argument symbol slúi ako rozde¾ovaè medzi jednotlivımi bajtmi
	short mask = 240;		// maska hornıch 4 bitov, bitovo = 1111 0000
	short high = (mask & byte) >> 4;	// vypoèítanie hornıch 4 bitov
	short low = 15 & byte;	// vypoèítanie dolnıch 4 bitov
	print_hex(high, line_buffer);	// vytlaèenie hornıch 4 bitov v hexadecimálnom tvare
	print_hex(low, line_buffer);		// vytlaèenie dolnıch 4 bitov v hexadecimálnom tvare
	strfcat(line_buffer, "%c", symbol);	// vytlaèenie poadovaného znaku z argumentov
}

void print_mac(char type, unsigned char* mac_address, char* line_buffer) {		// funkcia vytlaèí mac adresu na obrazovku
	short i = 0;		// inicializácia pomocnej premennej, ktorá poslúi pre cyklus
	if (type==0) strfcat(line_buffer, "Source MAC --> ");		// ak sa typ argumentu rovná nule, tak sa bude tlaèi zdrojová mac adresa
	else if (type==1) strfcat(line_buffer, "Destination MAC --> ");	// v opaènom prípade sa bude tlaèi cielová mac adresa
	for (i = 0; i < 6; i++) {	// cyklus
		if (i==5) print_byte(mac_address[i], '\0', line_buffer); 	// ak sa jedná o vytlaèenie posledného bajtu, tak za mac adresov sa vytlaèí prádny znak
		else print_byte(mac_address[i], ':', line_buffer);	// v opaènom prípade za koncom bajtu sa vytlaèí znak :
	}
	if (type != 2) strfcat(line_buffer, "\n");	// posunutie na novı riadok
}

void print_frame(int start, unsigned char* buffer, int frame_length, char* line_buffer) {		// funkcia vytlaèí celı rámec pod¾a zaèiatku rámca a celkovej dåky rámca
	int i = 0;		// inicializácia pomocnej premennej
	short byte_counter = 0;		// inicializácia premennej na poèítanie bajtov
	
	for (i = start; i < start + frame_length; i++) {	// cyklus, ktorı bude tlaèi jednotlivé bajty
		if (byte_counter == 8) strfcat(line_buffer, " ");		// ak sa poèítadlo bajtov rovná 8, tak vytlaè medzeru
		if (byte_counter == 16) {		// ak sa poèítadlo bajtov rovná 16
			strfcat(line_buffer, "\n");		// prejdi na novı riadok
			byte_counter = 0;	// natav poèítadlo bajtov na 0
		}
		print_byte(buffer[i], ' ', line_buffer);		// vytlaè bajt na pozicií i
		byte_counter ++;	// inkrementuj poèítadlo bajtov
	}
	strfcat(line_buffer, "\n\n");		// prejdi na novı riadok
}

unsigned short cut_type(int start, unsigned char* buffer) {		// funkcia vystrihne z buffera typ èíslo, ktoré bude pouíté ako typ protokolu
	unsigned short result = 0;		// inicializácia návratovej hodnoty
	result = (buffer[start] << 8) + buffer[start + 1];	// vypoèítanie návratovej hodnoty z èísel z buffera
	return result;	// návratová hodnota predstavuje èíslo, ktoré neskôr bude oznaèova typ protokolu
}

int str_to_int(const char* string) {	// funkcia prevedie string na celoèíselnú hodnotu resp. integer
	int i = 0;		// inicializácia pomocnej premennej
	int result = 0;		// inicializácia návratovej hodnoty
	while (string[i]!='\n') {	// cyklus, ktorı postupne prechádza string a konvertuje string na celé èíslo
		result *= 10; 	// násobenie návratovej hodnoty desiatimi
		result += (string[i] - 48);		// pripoèítanie èíselnej hodnoty zo stringu
		i++;		// inkrementácia pomocnej premennej
	}
	return result;	// návratová hodnota je poskladané celé èíslo (int)
}

int get_ethernet_IEEE() {		// funkcia vráti celé èíslo, ktoré predstavuje hranicu medzi ethernet II a IEEE
	int result = 0;		// inicializácia návratovej hodnoty
	char* line = (char*) malloc(80 * sizeof(char));		// inicializácia buffera, ktorı bude èíta zo súboru riadky	
	FILE* file = fopen(CONSTANTS_FILE, "r");		// otvorenie súbora Constants.txt na èítanie
	while (fgets(line, 80, file)) {		// pokia¾ sa dá èita zo súboru
		if ((strcmp(line, "__ETHERNET IEEE__\n")) == 0) {	// porovnaj preèítanı riadok s danım stringom
			fgets(line, sizeof(line), file);	// ak sa rovnajú preèítaj ïalší riadok, kde sa nachádza dané èíslo
			result = str_to_int(line);	 // konvertuj èíslo zo stringu do int-u
			break;	//ukonèi cyklus
		}
	}
	
	free(line);		// uvo¾nenie pamäti
	fclose(file);	// zatvorenie súboru
	return result;	// návratová hodnota je celé èíslo preítané zo súboru
}

unsigned short cut_protocol_number(char* line, char* string) {		// funkcia vystrihne z pola line èíslo protokolu
	int i = 0;		// inicializácia pomocnej premennej pri cykloch
	unsigned short result = 0;		// inicializácia návratovej hodnoty
	while (line[i] != ' ') {	// zaèiatok cyklu, kım sa znak na pozicií i nerovná medzere tak
		if (line[i] == '_' || line[i] == '\n') return 0; // ak sa rovná špecialnym znakom ukonèi funkciu s návratovou hodnotou 0
		result *= 10;	// vynásob vısledok 10
		result += (line[i] - 48);	// pripoèítaj èíslenú hodnotu na pozícií i
		i++;		// inkrement pomocnej premennej
	}
	
	i++;	// inkrement pomocnej premennej
	
	int k = 0;		// inicializácia pomocnej premennej k
	while (line[i] != '\n') {	// zaèiatok cyklu, kım sa znak na pozicií nerovná ukonèeniu riadku
		string[k] = line[i];	// do pomocného stringu zapíš meno protokolu
		i++;	// inkrementuj pomocnú premennú i
		k++;	// inkrementuj pomocnú premennú k
	}
	string[k] = '\0';	// na koniec pomocného stringu treba zapísa ukonèovací znak
	return result;	// návratová hodnota je èíslo protokolu naèítaného zo súboru
}

char* get_protocol_name(unsigned short type) {		// funkcia otvorí súbor a pod¾a parametru type vráti názov protokolu
	char* result_string = (char*) malloc(15 * sizeof(char));	// inicializácia stringu resp. pola znakov
	char* line = (char*) malloc(80 * sizeof(char));		// inicializácia buffera, ktorı bude èíta zo súboru riadky
	FILE* file = fopen(CONSTANTS_FILE, "r");	// otvorenie súbora Constants.txt na èítanie
	
	while (fgets(line, 80, file)) {		// pokia¾ sa dá èita zo súboru
		if (type == cut_protocol_number(line, result_string)) break;	// porovnaj argument type a èíslo protokolu, ak sa rovanjú ukonèi cyklus
		result_string[0] = '\0';	// ak sa nerovnajú vynuluj string
	}
	
	fclose(file);	// zatvorenie súboru
	free(line);		// uvolnenie pamäti
	return result_string;	// návratová hodnota je názov protokolu, ktorı spåòa podmienky
}

int write_in_string(unsigned char number, char* ip_string, int length) {	// funkcia zapíše poadované èíslo do ip_stringu
	if (number == 0) {	// ak sa argument rovná nule
		ip_string[length] = '0';	// zapíš nulu do stringu
		length++;	// inkrementuj dåku stringu
		return length;		// vrá dåku stringu
	}
	
	short temp_number = 0;	// inicializácia pomocnej premennej
	short number_length = 0;	// inicializácia pomocnej premennej
	
	while (number != 0) {	// kım sa èíslo nerovná nule
		temp_number *= 10;		// vynásob pomocné èislo desiatimi
		temp_number += (number % 10);	// pripoèítaj k pomocnému èíslu zvyšok po delení desiatimi
		number = number / 10;	// delenie èísla desiatimi
		number_length++;	// inkrementácia dåky èísla
	}
	
	while (number_length != 0) {	// kım dåka èísla sa nerovná nule
		ip_string[length] = (temp_number % 10) + 48;	// pridaj zvyšok po delení 10 do stringu
		length++;	// inkrementuj dåku stringu
		temp_number /= 10;	// vyde¾ pomconé èíslo desiatimi
		number_length--;	// dekrementuj dåku èísla
	}
	
	return length;	// návratová hodnota je dåka stringu
}

char* get_ip(int start, unsigned char* buffer) {		// funkcia vráti string s ip adresou na základe buffera a argumentu start
	char* ip_string = (char*) malloc(16 * sizeof(char));	// alokácia stringu pre ip adresu
	int i = 0;	// inicializácia pomocnej premennej
	int ip_string_len = 0;		// inicializácia dåky ip stringu
	for (i = 0; i < 4; i++) {	// for cyklus, ktorı sa bude opakova 4x
		ip_string_len = write_in_string(buffer[start+i], ip_string, ip_string_len);	// zapísanie èísla z buffera do ip_stringu
		if (i < 3) ip_string[ip_string_len] = '.';	// ak premenná i je menšia ako tri zapíš do stringu aj bodku
		ip_string_len++;	// inkrementácia dåky stringu
	}
	ip_string[ip_string_len-1] = '\0';	// na koniec ip stringu zapíš ukonèovací znak
	return ip_string;	// návratová hodnota je string s ip adresou z buffera a posunu
}

#define FIN 1
#define SYN 2
#define RST 4
#define PSH 8
#define ACK 16
void print_tcp_flags(unsigned char tcp_flags, char* line_buffer) {		// funckia vytlaèí na základe parametrov všetky flagy tcp protokolu
	if (tcp_flags & FIN) strfcat(line_buffer, " [FIN]");
	if (tcp_flags & SYN) strfcat(line_buffer, " [SYN]");
	if (tcp_flags & RST) strfcat(line_buffer, " [RST]");
	if (tcp_flags & PSH) strfcat(line_buffer, " [PSH]");
	if (tcp_flags & ACK) strfcat(line_buffer, " [ACK]");
	
	strfcat(line_buffer, "\n");	// na konci sa vytlaèí znak nového riadku
}

void print_tcp(int start, unsigned char* buffer, char* line_buffer) {		// funkcia vytlaèí na základe èísiel portov príslušné vnorené tcp protokoly
	unsigned short source_port = (short) (buffer[start] << 8) + buffer[start + 1];		// inicializácia a nastavenie zdrojvého portu
	unsigned short destination_port = (short) (buffer[start + 2] << 8) + buffer[start + 3];	// inicializácia a nastavenie cielového portu
	char* protocol_name_src = get_protocol_name(source_port);	// priradenie názvu protokolu pod¾a èísla zdrojového portu
	char* protocol_name_dst = get_protocol_name(destination_port);	// priradenie názvu protokolu pod¾a èísla cielového portu
	
	if ((strcmp(protocol_name_src, "FTP_DATA")) == 0 || (strcmp(protocol_name_dst, "FTP_DATA")) == 0) {
		strfcat(line_buffer, "FTP_DATA (File Transfer Protocol)\n");
	}
	else if ((strcmp(protocol_name_src, "FTP_CONTROL")) == 0 || (strcmp(protocol_name_dst, "FTP_CONTROL")) == 0) {
		strfcat(line_buffer, "FTP_CONTROL (File Transfer Protocol)\n");
	}
	else if ((strcmp(protocol_name_src, "SSH")) == 0 || (strcmp(protocol_name_dst, "SSH")) == 0) {
		strfcat(line_buffer, "SSH (Secure Shell)\n");
	}
	else if ((strcmp(protocol_name_src, "TELNET")) == 0 || (strcmp(protocol_name_dst, "TELNET")) == 0) {
		strfcat(line_buffer, "TELNET\n");
	}
	else if ((strcmp(protocol_name_src, "HTTP")) == 0 || (strcmp(protocol_name_dst, "HTTP")) == 0) {
		strfcat(line_buffer, "HTTP (Hypertext Transfer Protocol)\n");
	}
	else if ((strcmp(protocol_name_src, "NETBIOS_SES")) == 0 || (strcmp(protocol_name_dst, "NETBIOS_SES")) == 0) {
		strfcat(line_buffer, "NetBIOS Session Service\n");
	}
	else if ((strcmp(protocol_name_src, "HTTPS")) == 0 || (strcmp(protocol_name_dst, "HTTPS")) == 0) {
		strfcat(line_buffer, "HTTPS (Hypertext Transfer Protocol Secure)\n");
	}
	
	free(protocol_name_src);	// uvo¾nenie pamäti
	free(protocol_name_dst);	// uvo¾nenie pamäti
	strfcat(line_buffer, "Source Port --> %d\n", source_port);	// vytlaèenie èísla zdrojového portu
	strfcat(line_buffer, "Destination Port --> %d\n", destination_port);	// vytlaèenie èísla cie¾ového portu
}

void print_udp(int start, unsigned char* buffer, char* line_buffer) {	// funkcia vytlaèí na základe èísiel portov príslušné vnorené udp protokoly
	unsigned short source_port = (short) (buffer[start] << 8) + buffer[start + 1];		// inicializácia a nastavenie zdrojvého portu
	unsigned short destination_port = (short) (buffer[start + 2] << 8) + buffer[start + 3];		// inicializácia a nastavenie cielového portu
	char* protocol_name_src = get_protocol_name(source_port);		// priradenie názvu protokolu pod¾a èísla zdrojového portu
	char* protocol_name_dst = get_protocol_name(destination_port);		// priradenie názvu protokolu pod¾a èísla cielového portu
	
	if ((strcmp(protocol_name_src, "DNS")) == 0 || (strcmp(protocol_name_dst, "DNS")) == 0) {
		strfcat(line_buffer, "DNS (Domain Name System)\n");
	}
	else if ((strcmp(protocol_name_src, "DHCP")) == 0 || (strcmp(protocol_name_dst, "DHCP")) == 0) {
		strfcat(line_buffer, "DHCP (Dynamic Host Configuration Protocol) ");
		unsigned short dhcp_type = buffer[start + 250];
		if (dhcp_type == 1) strfcat(line_buffer, "- Discover\n");
		else if (dhcp_type == 2) strfcat(line_buffer, "- Offer\n");
		else if (dhcp_type == 3) strfcat(line_buffer, "- Request\n");
		else if (dhcp_type == 5) strfcat(line_buffer, "- ACK\n");
		else strfcat(line_buffer, "\n");
	}
	else if ((strcmp(protocol_name_src, "TFTP")) == 0 || (strcmp(protocol_name_dst, "TFTP")) == 0) {
		strfcat(line_buffer, "TFTP (Trivial File Transfer Protocol)\n");
	}
	else if ((strcmp(protocol_name_src, "NBNS")) == 0 || (strcmp(protocol_name_dst, "NBNS")) == 0) {
		strfcat(line_buffer, "NetBIOS Name Service\n");
	}
	else if ((strcmp(protocol_name_src, "NETBIOS_DGRAM")) == 0 || (strcmp(protocol_name_dst, "NETBIOS_DGRAM")) == 0) {
		strfcat(line_buffer, "NetBIOS Datagram Service\n");
	}
	else if ((strcmp(protocol_name_src, "SNMP")) == 0 || (strcmp(protocol_name_dst, "SNMP")) == 0) {
		strfcat(line_buffer, "SNMP (Simple Network Management Protocol)\n");
	}
	else if ((strcmp(protocol_name_src, "RIPv")) == 0 || (strcmp(protocol_name_dst, "RIPv")) == 0) {
		strfcat(line_buffer, "RIPv%d (Routing Information Protocol version %d)\n", buffer[start + 9], buffer[start + 9]);
	}
	else if ((strcmp(protocol_name_src, "SSDP")) == 0 || (strcmp(protocol_name_dst, "SSDP")) == 0) {
		strfcat(line_buffer, "SSDP (Simple Service Discovery Protocol)\n");
	}
	else if ((strcmp(protocol_name_src, "MDNS")) == 0 || (strcmp(protocol_name_dst, "MDNS")) == 0) {
		strfcat(line_buffer, "MDNS (Multicast DNS)\n");
	}
	else if ((strcmp(protocol_name_src, "LLMNR")) == 0 || (strcmp(protocol_name_dst, "LLMNR")) == 0) {
		strfcat(line_buffer, "LLMNR (Link-Local Multicast Name Resolution)\n");
	}
	else if ((strcmp(protocol_name_src, "HSRP")) == 0 || (strcmp(protocol_name_dst, "HSRP")) == 0) {
		strfcat(line_buffer, "HSRP (Cisco Hot Standby Router Protocol)\n");	
	}
	
	free(protocol_name_src);	// uvo¾nenie pamäti
	free(protocol_name_dst);	// uvo¾nenie pamäti
	strfcat(line_buffer, "Source Port --> %d\n", source_port);		// vytlaèenie èísla zdrojového portu
	strfcat(line_buffer, "Destination Port --> %d\n", destination_port);		// vytlaèenie èísla cie¾ového portu
}

void print_icmp(int start, unsigned char* buffer, char* line_buffer) {		// funkcia vytlaèí podrobnosti o protokole ICMP
	strfcat(line_buffer, " - Type --> ");		// vytlaèenie textu
	char icmp_type = buffer[start];		// nastavenie premennej type 
	char icmp_code = buffer[start + 1];		// nastavenie premennej code
	
	if (icmp_type == 0) strfcat(line_buffer, "Reply");
	else if (icmp_type == 3) {
		strfcat(line_buffer, "Destination Unreachable");
		if (icmp_code == 0) strfcat(line_buffer, " -- Net Unreachable");
		else if (icmp_code == 1) strfcat(line_buffer, " -- Host Unreachable");
		else if (icmp_code == 2) strfcat(line_buffer, " -- Protocol Unreachable");
		else if (icmp_code == 3) strfcat(line_buffer, " -- Port Unreachable");
	}
	else if (icmp_type == 5) strfcat(line_buffer, "Redirect");
	else if (icmp_type == 8) strfcat(line_buffer, "Request");
	else if (icmp_type == 11) {
		strfcat(line_buffer, "Time Exceeded");
		if (icmp_code == 0) strfcat(line_buffer, " -- Time to Live Exceeded in Transit");
		else if (icmp_code == 1) strfcat(line_buffer, " -- Fragment Reassembly Time Exceeded");
	}
	else if (icmp_type == 30) strfcat(line_buffer, "Traceroute");
	strfcat(line_buffer, "\n");		// vytlaèenie ukonèovacieho znaku
}

void print_ethernet_ip_protocol(int start, unsigned char* buffer, struct List** ip_list, char* line_buffer) {	// funkcia vytlaèí podrobnosti o IP prípadne aj vnorené protokoly pod IP
	char ip_info = buffer[start];		// nastavenie premennej ip info
	char ip_info_high = (ip_info >> 4) & 15;		// osamostatnenie hornıch 4 bitov
	char ip_info_low = ip_info & 15;		// osamostatnenie dolnıch 4 bitov
	if (ip_info_high == 4) {
		strfcat(line_buffer, "\nIPv4 (IHL %d)\n", ip_info_low);		// vypísanie informácií o IPv4
	}
	strfcat(line_buffer, "Source IP --> %s\n", get_ip(start + 12, buffer));		// vypísanie zdrojovej ip adresy
	strfcat(line_buffer, "Destination IP --> %s\n", get_ip(start + 12 + 4, buffer));	// vypísanie cielovej ip adresy
	
	*ip_list = add_ip_address_to_list(convert_ip(get_ip(start+ 12, buffer)), *ip_list);		// pridanie adresy to listu ip adries
	
	short protocol_type = (short) buffer[start + 9];		// premenná pre èíslo protokolu
	if ((strcmp(get_protocol_name(protocol_type), "TCP")) == 0) {
		strfcat(line_buffer, "TCP (Transmission Control Protocol)");
		print_tcp_flags(buffer[start + 33], line_buffer);
		print_tcp(start + 12 + 4 + 4, buffer, line_buffer);
	}
	else if ((strcmp(get_protocol_name(protocol_type), "UDP")) == 0) {
		strfcat(line_buffer, "UDP (User Datagram Protocol)\n");
		print_udp(start + 12 + 4 + 4, buffer, line_buffer);
	}
	else if ((strcmp(get_protocol_name(protocol_type), "ICMP")) == 0) {
		strfcat(line_buffer, "ICMP (Internet Control Message Protocol)");
		print_icmp(start + 12 + 4 + 4 + (ip_info_low * 4 - 20), buffer, line_buffer);
	}
	else if ((strcmp(get_protocol_name(protocol_type), "EIGRP")) == 0)
		strfcat(line_buffer, "EIGRP (Enhanced Interior Gateway Routing Protocol)\n");
}

int analyze(char* path, char filter, FILE* output) {		// funkcia analyzuje jednotlivé rámce v súbore .pcap
	
	unsigned char* line_buffer = (char*) malloc((6*4096)*sizeof(char));
	line_buffer[0] = '\0';
 	
	int temp_int = get_ethernet_IEEE();		// inicializácia a nastavenie pomocnej premennej
	
	
	FILE *fileptr;		// inicializácia smerníka
	unsigned char *buffer;		// inicializácia buffera
	long filelen;		// inicializácia premennej dåky súboru

	fileptr = fopen(path, "rb");  	// otvorenie súboru ako read byte
	fseek(fileptr, 0, SEEK_END);	// prejdenie na koniec súboru          
	filelen = ftell(fileptr);        // nastavenie dåky súboru     
	rewind(fileptr);             // návrat na zaèiatok súboru         

	buffer = (unsigned char *) malloc(filelen * sizeof(unsigned char)); 	// buffer pre bajty zo súboru
	fread(buffer, filelen, 1, fileptr); 		// naèítaj súbor do buffera
	fclose(fileptr); 	// zatvor súbor
	
	struct List* ip_list = NULL;		// inicializácia spájaného zoznamu s ip adresami
		
	int i = 32;			// inicializácia pomocnej premennej
	int frame_number = 1;		// inicializácia premennej, ktorá oznaèuje poèet rámcov
	int frame_length = 0;		// inicializácia premennej, ktorá oznaèuje ve¾kos rámca
	unsigned char* destination_mac_address = NULL;		//inicializácia premennej pre cie¾ovú mac adresu
	unsigned char* source_mac_address = NULL;		// inicializácia premennej pre zdrojovú mac adresu
	
	unsigned short type = 0;		// inicializácie premennej pre typ protokolu
	char* ethertype;	// inicializácia premennej pre stringovı typ protokolu
	
	while (i < filelen) {		// cyklus pre vypísanie všetkıch rámcov
		frame_length = build_frame_length(buffer[i], buffer[i+1], buffer[i+2], buffer[i+3]);	// vytvorenie dåky rámca
		strfcat(line_buffer, "-----------------------------------------------------\n");		// vytlaèenie odde¾ovaèa
		strfcat(line_buffer, "Frame Number --> %d\nFrame length available to pcap --> %d\n", frame_number, frame_length);		// vytlaèenie dåky rámca
		if (frame_length <= 60) strfcat(line_buffer, "Frame length sent by medium --> 64\n\n");		// vytlaèenie dåky rámca
		else strfcat(line_buffer, "Frame length sent by medium --> %d\n\n", frame_length + 4);		// vytlaèenie dåky rámca
		
		destination_mac_address = cut_mac_address(i+8, buffer);		// nastavenie cie¾ovej adresy
		source_mac_address = cut_mac_address(i+8+6, buffer);		// nastavenie zdrojovej adresy
		type = cut_type(i+8+6+6, buffer);	// nastavenie premennej type
		
		if (type > temp_int) {
			strfcat(line_buffer, "Ethernet II\n");
			print_mac(0, source_mac_address, line_buffer);
			print_mac(1, destination_mac_address, line_buffer);
			ethertype = get_protocol_name(type);
			
			if ((strcmp(ethertype, "IPV4")) == 0) {
				print_ethernet_ip_protocol(i+8+6+6+2, buffer, &ip_list, line_buffer);
			}
			else if ((strcmp(ethertype, "IPV6")) == 0) {
				strfcat(line_buffer, "IPv6\n");
			}
			else if ((strcmp(ethertype, "ARP")) == 0) {
				strfcat(line_buffer, "ARP (Address Resolution Protocol)");
				short opcode = (buffer[i+8+6+6+8] << 8) + buffer[i+8+6+6+8+1];
				if (opcode == 1) {
					strfcat(line_buffer, " - Request");
					strfcat(line_buffer, "\nWho has %d.%d.%d.%d? Tell %d.%d.%d.%d", 
						buffer[i+8+6+6+8+18], buffer[i+8+6+6+8+19], buffer[i+8+6+6+8+20], buffer[i+8+6+6+8+21], 
						buffer[i+8+6+6+8+8], buffer[i+8+6+6+8+9], buffer[i+8+6+6+8+10], buffer[i+8+6+6+8+11]);
				}
				else if (opcode == 2) {
					strfcat(line_buffer, " - Reply");
					strfcat(line_buffer, "\n%d.%d.%d.%d at ", 
					buffer[i+8+6+6+8+8], buffer[i+8+6+6+8+9], buffer[i+8+6+6+8+10], buffer[i+8+6+6+8+11]);
					print_mac(2, source_mac_address, line_buffer);
				}
				strfcat(line_buffer, "\n");
			}
			else if ((strcmp(ethertype, "LOOP")) == 0) {
				strfcat(line_buffer, "LOOP (Configuration Testing Protocol)\n");
			}
			else if ((strcmp(ethertype, "LLDP")) == 0) {
				strfcat(line_buffer, "LLDP (Link Layer Discovery Protocol)\n");
			}
		}
		else {
			strfcat(line_buffer, "IEEE ");
			short iee_type = buffer[i + 8 + 14];
			char* string_type = get_protocol_name(iee_type);
			if ((strcmp(string_type, "SNAP")) == 0) {
				strfcat(line_buffer, "802.3 LLC + SNAP ");
				short temp_number = (buffer[i + 8 + 20] << 8) + buffer[i + 8 + 21];
				free(string_type);
				string_type = get_protocol_name(temp_number);
				
				if ((strcmp(string_type, "CDP")) == 0) strfcat(line_buffer, "- Cisco Discovery Protocol\n");
				else if ((strcmp(string_type, "IPV4")) == 0) strfcat(line_buffer, "- IPv4\n");
				else if ((strcmp(string_type, "IPV6")) == 0) strfcat(line_buffer, "- IPv6\n");
				else if ((strcmp(string_type, "ARP")) == 0) strfcat(line_buffer, "- ARP\n");
				else if ((strcmp(string_type, "NOVELL_IPX")) == 0) strfcat(line_buffer, "- Novell IPX\n");
				else if ((strcmp(string_type, "APPLE_TALK")) == 0) strfcat(line_buffer, "- AppleTalk\n");
				else if ((strcmp(string_type, "APPLE_AARP")) == 0) strfcat(line_buffer, "- AppleTalk AARP\n");
				else if ((strcmp(string_type, "DTP")) == 0) strfcat(line_buffer, "- Dynamic Trunk Protocol\n");
				else strfcat(line_buffer, "\n");
			}
			else if ((strcmp(string_type, "RAW")) == 0) {
				strfcat(line_buffer, "802.3 Raw - IPX ");
				short temp_number = (buffer[i + 8 + 30] << 8) + buffer[i + 8 + 31];
				free(string_type);
				string_type = get_protocol_name(temp_number);
				
				if ((strcmp(string_type, "RIP")) == 0) strfcat(line_buffer, "- Routing Information Protocol\n");
				else if ((strcmp(string_type, "SAP")) == 0) strfcat(line_buffer, "- Service Advertising Protocol\n");
				else if ((strcmp(string_type, "NBIPX")) == 0) strfcat(line_buffer, "- NetBIOS\n");
				else if ((strcmp(string_type, "IPX")) == 0) strfcat(line_buffer, "- Internetwork Packet Exchange\n");
				else if ((strcmp(string_type, "TCP_IPX")) == 0) strfcat(line_buffer, "- TCP over IPX\n");
				else if ((strcmp(string_type, "UDP_IPX")) == 0) strfcat(line_buffer, "- UDP over IPX\n");
				else strfcat(line_buffer, "\n");
			}
			else {
				strfcat(line_buffer, "802.3 LLC ");
				
				if ((strcmp(string_type, "NULL_SAP")) == 0) strfcat(line_buffer, "- NULL SAP\n");
				else if ((strcmp(string_type, "LLC_SM_I")) == 0) strfcat(line_buffer, "- LLC Sublayer Management Individual\n");
				else if ((strcmp(string_type, "LLC_SM_G")) == 0) strfcat(line_buffer, "- LLC Sublayer Management Group\n");
				else if ((strcmp(string_type, "STP")) == 0) strfcat(line_buffer, "- Spanning Tree Protocol\n");
				else if ((strcmp(string_type, "ISI_IP")) == 0) strfcat(line_buffer, "- ISI IP\n");
				else if ((strcmp(string_type, "X25_PLP")) == 0) strfcat(line_buffer, "- X25.PLP\n");
				else if ((strcmp(string_type, "LAN_MNGMT")) == 0) strfcat(line_buffer, "- LAN Management\n");
				else if ((strcmp(string_type, "LLC_IPX")) == 0) {
					strfcat(line_buffer, "- IPX ");
					short temp_number = (buffer[i + 8 + 33] << 8) + buffer[i + 8 + 34];
					free(string_type);
					string_type = get_protocol_name(temp_number);
					if ((strcmp(string_type, "SAP")) == 0) strfcat(line_buffer, "- Service Advertising Protocol\n");
					else if ((strcmp(string_type, "NBIPX")) == 0) strfcat(line_buffer, "NetBIOS over IPX\n");
					else strfcat(line_buffer, "\n");
				}
				else if ((strcmp(string_type, "LLC_NETBIOS")) == 0) strfcat(line_buffer, "- NetBIOS\n");
				else if ((strcmp(string_type, "NBIPX")) == 0) strfcat(line_buffer, "- NetBIOS over IPX\n");
			}
			
			free(string_type);	
			print_mac(0, source_mac_address, line_buffer);		// vytlaèenie zdrojovej mac adresy
			print_mac(1, destination_mac_address, line_buffer);	// vytlaèenie cielovej mac adresy
		}
		
		strfcat(line_buffer, "\n");
		print_frame(i+8, buffer, frame_length, line_buffer);		// vytlaèenie celého ramca
		i += frame_length + 16;
		frame_number++;
		strfcat(line_buffer, "\n");
		free(destination_mac_address);		// uvo¾nenie pamäte
		free(source_mac_address);		// uvo¾nenie pamäte
		
		// následnı if-else block sa stará o vypísanie konkrétneho filtra
		if (filter == 0)fprintf(output, "%s", line_buffer);
		else if (filter == 1 && strstr(line_buffer, "ARP")) fprintf(output, "%s", line_buffer); 
		else if (filter == 2 && strstr(line_buffer, "HTTP")) fprintf(output, "%s", line_buffer);
		else if (filter == 3 && strstr(line_buffer, "HTTPS")) fprintf(output, "%s", line_buffer);
		else if (filter == 4 && strstr(line_buffer, "TELNET")) fprintf(output, "%s", line_buffer);
		else if (filter == 5 && strstr(line_buffer, "SSH")) fprintf(output, "%s", line_buffer);
		else if (filter == 6 && strstr(line_buffer, "FTP")) fprintf(output, "%s", line_buffer);
		else if (filter == 7 && strstr(line_buffer, "TFTP")) fprintf(output, "%s", line_buffer);
		else if (filter == 8 && strstr(line_buffer, "ICMP")) fprintf(output, "%s", line_buffer);
		line_buffer[0] = '\0';
		}
	free(line_buffer);		// uvo¾nenie pamäte
	
	
	if (filter == 0) {
		fprintf(output, "-----------------------------------------------------\n");		// vytlaèenie odde¾ovaèa
		unsigned int max_count = 0;		// inicializácia premennej poèítadla maxím
		struct List* temp = ip_list;	// inicializácia a nastavenie pomocného smerníka
		unsigned int maximum = ip_list->count;		// inicializácia a nastavenie maxima
		fprintf(output, "Source IPv4 Addresses	Count\n");		// informaèná správa
		while (temp != NULL) {		// prechod celım spájanım zoznamom a vytlaèenie jednotlivıch ip adries s príslušnımi poèetnosami
			fprintf(output, "%d.%d.%d.%d		%d\n", (temp->ip_address >> 24) & 255, (temp->ip_address >> 16) & 255, 
				(temp->ip_address >> 8) & 255, temp->ip_address & 255, temp->count);
			if (temp->count > maximum) {
				maximum = temp->count;
				max_count = 0;
			}
			if (temp->count == maximum) max_count++;
			temp = temp->next;
		}
	
		temp = ip_list; // vytlaèenie najpoèetnejších ip adries/ ip adresy
		if (max_count > 1) fprintf(output, "\nHighest number of packets %d was sent by these IP addresses:\n", maximum);
		else if (max_count == 1) fprintf(output, "\nHighest number of packets %d was sent by this IP address:\n", maximum);
		while (temp != NULL) {
			if (temp->count == maximum) fprintf(output, "%d.%d.%d.%d\n", (temp->ip_address >> 24) & 255, (temp->ip_address >> 16) & 255, 
			(temp->ip_address >> 8) & 255, temp->ip_address & 255);
			temp = temp->next;
		}
	}

	
	
	
	free(buffer);	// uvo¾nenie pamäti
	free(ip_list);	// uvo¾nenie pamäti
	return 0;
}

struct Cmd* decode(char* buffer) {		// funkcia na základe pouívate¾ského vstupu vo formáte string, vyparsuje danı string a prerobí ho do štruktúry Cmd
	struct Cmd* result = (struct Cmd*) malloc(sizeof(struct Cmd));	// inicializácia smernáka na Cmd
	result->path[0] = '\0';		// inicializácia jednotlivıch premennıch
	result->filename[0] = '\0';
	result->redirect = 0;
	result->filter = 0;
	char filter[10];
	int i = 0;
	
	
	
	while (buffer[i] != ' ') {	// naplnenie premennej path (abosolutná cesta k input súboru)	
		if (buffer[i] == '\0') {
			result->path[i] = '\0';
			return result;
		}
		result->path[i] = buffer[i];
		i++;
	}
	
	result->path[i] = '\0';	
	i++;
	
	int k = 0;
	if (buffer[i] == '-') {		//naplnenie premennej filter, pod¾a elaného protokolu
		i++;
		while (buffer[i] != ' ') {
			if (buffer[i] == '\0') break;
			filter[k] = buffer[i];
			k++;
			i++;
		}	
		filter[k] = '\0';
		i++;
		if ((strcmp(filter, "ARP")) == 0) result->filter = 1;
		else if ((strcmp(filter, "HTTP")) == 0) result->filter = 2;
		else if ((strcmp(filter, "HTTPS")) == 0) result->filter = 3;
		else if ((strcmp(filter, "TELNET")) == 0) result->filter = 4;
		else if ((strcmp(filter, "SSH")) == 0) result->filter = 5;
		else if ((strcmp(filter, "FTP")) == 0) result->filter = 6;
		else if ((strcmp(filter, "TFTP")) == 0) result->filter = 7;
		else if ((strcmp(filter, "ICMP")) == 0) result->filter = 8;
	}
	

	
	k = 0;
	if (buffer[i] == '>' && buffer[i+1] == '>'){ //naplnenie premennej filename (output file pre vıpisy rámcov)
		i += 3;
		while(buffer[i] != ' ') {
			if (buffer[i] == '\0') break;
			result->filename[k] = buffer[i];
			i++;
			k++;
		}
		result->redirect = 1;
		result->filename[k] = '\0';
	}
	
	
	return result;		// návratová hodnota je vytvorenı smerník, ktorı bude naplnenı potrebnımi dátami
}


int main() {
	char* command = (char*) malloc(150 * sizeof(char));			//alokácia pamäte pre príkaz od pouívate¾a	
	struct Cmd* scommand = NULL;								//inicializácia smerníka pre vyparsovanı príkaz
	
	printf("Enter Command or valid Path to your .pcap file >> ");
	while (scanf("%[^\n]%*c", command)) {						// naskenuj vstup od pouívate¾a
		if ((strcmp((const char*) command,"end")) == 0) break;		//ak pouívate¾ zadal príkaz "end" ukonèi program
		else if ((strcmp((const char*) command,"help")) == 0) {		//ak pouívate¾ zadal príkaz "help" vypíš help menu
			printf("Enter Path to your .pcap file to run the program\n\tType '>> filename' after your Path to redirect output to your file (.txt format)\n\tType -PROTOCOL_NAME after your Path to filter the frames\n");
			printf("----------------------------------------------\nType 'end' to terminate the program\n");
		}
		else {			//spracovanie príkazu a následná analıza rámcov
			scommand = decode(command);		// funkcia, ktorá vyparsuje príkaz a premení ho na vhodnejšiu štruktúru
			if (scommand->redirect == 0) analyze(scommand->path, scommand->filter, stdout);		// ak sa redirect nenastavil na 1 tak vypíš rámce na štandardnı vıstup
			else {		// v opaènom prípade otvor output file a nakopíruj jednotlivé rámce doòho
				printf("\nOpening .txt file %s\n", scommand->filename);	
				FILE* file = fopen(scommand->filename, "w");
				printf("Analyzing ...\n");
				analyze(scommand->path, scommand->filter, file);
				printf("Closing .txt file %s\n", scommand->filename);
				fclose(file);		// zatvorenie súboru
			}
			free(scommand);		// uvo¾nenie pamäti
			printf("\nDone!\n\n");	// informáèná správa, e všetky rámce sa vypísali
		}
		printf("Enter Command or valid Path to your .pcap file >> ");		// správa pre pouívate¾a, e môe zada ïalší príkaz
	}
	free(command);		// uvo¾nenie pamäti
	
	return 0;
}
