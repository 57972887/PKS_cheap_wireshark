#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CONSTANTS_FILE "Constants.txt"		//textov� s�bor, kde sa nach�dzaj� kon�tanty resp. ��sla jednotliv�ch protokolov


struct Cmd {			// �trukt�ra pre zad�vanie pr�kazov po spusten� programu
	char path[80];			// premenn� na uchovanie absolutnej cesty k .pcap s�boru
	char filename[80];		// premenn� na uchovanie absolutnej cesty k v�stpun�mu s�boru
	char filter;			// premenn� na uchovanie ��sla protokolu, ktor� sa bude filtrova�
	char redirect;			// premenn�, ktor� sl��i na presmerovanie v�stupu
};

struct List {		// �trukt�ra sp�jan�ho zoznamu, ktor� uchov�va jednotliv� ip adresy a ich po�etnos� v konkr�tnom .pcap s�bore
	unsigned int ip_address;	// 4 bajtov� ��slo, ktor� ozna�uje ip adresu
	unsigned int count;		// pr�slu�n� ��slo k ip adrese, ktor� ozna�uje ko�ko kr�t sa dan� ip adresa v .pcap s�bore nach�dza
	struct List* next;		// smern�k na �al�� z�znam
};

void strfcat(char* source, char* format, ...) {		// funkcia, ktor� sp�ja form�tovan� stringy
	char buffer[2048];	
	va_list args;
	
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);
	
	strcat(source, buffer);
}

unsigned int convert_ip(char* string_ip) {		// funkcia konvertuje textov� formu ip adresy na ��seln�, aby sa mohla zap�sa� do sp�jan�ho zoznamu
	
	unsigned int result = 0;	// inicializ�cia v�sledku na 0
	unsigned int temp_result = 0;	// inicializ�cia premnennej na 0
	short string_length = strlen(string_ip);	// inicializ�cia premennej, ktor� ozna�uje d�ku stringu
	short offset  = 24;		// posun, ktor� sa bude pou��va� pri konverzi� ip adresy
	int i = 0;	// inicializ�cia pomocnej premennej
	
	while (i <= string_length) {	// vykon�vaj cyklus pokial sa i nerovn� d�ke stringu
		if (string_ip[i] == '.' || i == string_length) {	// ak sa znak na pozici� i rovn� bodke alebo sme na konci stringu tak vykonaj nasleduj�ce
			i++;	// inkrementuj premenn� i
			result += (temp_result << offset);	// pripo��taj k v�sledku �iastkov� v�sledok
			temp_result = 0; 	// nastav �iastkov� v�sledok na 0
			offset -= 8;	// odpo��taj od posunu ��slo 8
			continue;	// pokra�uj vo vykon�van� cyklu
		}
		temp_result *= 10;	// vyn�sob �iastkov� v�sledok 10
		temp_result += string_ip[i] - 48;	// pripo��taj k �iastkov�mu v�sledku ��slo na poz�ci� i zo stringu
		i++;	// inkrementuj premenn� i
	}
	
	return result;		// n�vratov� hodnota je cel� ��slo bez znamienka a predstavuje konvertovan� ip adresu
}

struct List* create_node(int ip_number) {	// funkcia vytvor� nov� uzol resp. z�znam do sp�jan�ho zoznamu
	struct List* node = (struct List*) malloc(sizeof(struct List));	// inicializ�cia premennej, alok�cia po�adovan�ho pam�ov�ho priestoru
	node->ip_address = ip_number;	// nastavenie premennej ip adresa
	node->count = 1;	// nastavenie premennej, ktor� ozna�uje v�skyt danej ip adresy na 1
	node->next = NULL;	// nastavenie smern�ka na �al�� z�znam na NULL
	return node;	// vr�tenie uzla pre �al�ie spracovanie
}

struct List* add_ip_address_to_list(unsigned int ip_number, struct List* ip_list) {		// funkcia, ktor� prid� do sprajan�ho zoznamu po�adovan� ip adresu, ak sa t�to ip adresa u� v sp�janom zozname vyskytuje tak sa iba pripo��ta po�etnos�
	if (ip_list == NULL) ip_list = create_node(ip_number);		// ak e�te �trukt�ra nebola inicializovan�, resp. neexistuje �iadny z�znam, tak vytvor prv� uzvol/z�znam
	else {
		struct List* temp = ip_list;	// v opa�nom pr�pade nastav premenn� temp na za�iatok zoznamu
		while (temp != NULL) {	// k�m existuj� z�znamy v zozname tak prech�dzaj jednotliv� z�znamy
			if (ip_number == temp->ip_address) {	// ak s� ip adresy zhodn�
				temp->count++;		// inkrementuj po�etnos� ip adresy
				break;		// ukon�i cyklus
			}
			if (temp->next == NULL) {		// ak sme pre�li v�etky z�znamy a nenastala zhoda v ip adres�ch, tak vytvor na konci nov� uzol/z�znam
				temp->next = create_node(ip_number);	// vytvorenie nov�ho z�znamu
				break;		// ukon�enie cyklu
			}
			else temp = temp->next;		// posun na �al�� z�znam
		}
	}
	return ip_list;		// n�vratov� hodnota je upraven� sp�jan� zoznam
}


int build_frame_length(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {	// funkcia zo �tyroch bajtov�ch ��sel zostav� jedno ��slo
	int frame_length = 0;	// inicializ�cia ve�kosti r�mca
	int offset = 8;		// inicializ�cia premmenej posunu
	frame_length = a + (b << offset) + (c << offset*2) + (d << offset*3);	// vypo��tanie premennej, ktor� ozna�uje d�ku r�mca zostaven� zo �tyroch bajtov�ch ��sel
	return frame_length;		// n�vratov� hodnota ozna�uje vypo��tan� d�ku r�mca
}

unsigned char* cut_mac_address(int start, unsigned char* buffer) {		// funkcia, ktor� z buffera vystrihne mac adresu pod�a premennej start
	unsigned char* result = (unsigned char*) malloc(6 * sizeof(unsigned char));		// inicializ�cia 6 bajtov pre ulo�enie mac adresy
	short i = 0;	// nastavenie pomocnej premennej pre cyklus
	for (i = 0; i < 6; i++) 
		result[i] = buffer[start+i];	// kop�rovanie mac adresy do premennej result
	
	return result;	// n�vratov� hodnota obsahuje prekop�rovan� mac adresu z buffera
}

void print_hex(int number, char* line_buffer) {		// funkcia konvertuje decim�lne ��slo na hexadecim�lne, resp. vytla�� miesto decim�lneho ��sla hexadecim�lne
		switch(number) {
		case (10) :
			strfcat(line_buffer, "A");	// ak sa po�adovan� ��slo rovn� 10 vytla� p�smeno A
			break;
		case (11) :
			strfcat(line_buffer, "B");	// ak sa po�adovan� ��slo rovn� 11 vytla� p�smeno B
			break;
		case (12) :
			strfcat(line_buffer, "C");	// ak sa po�adovan� ��slo rovn� 12 vytla� p�smeno C
			break;
		case (13) :
			strfcat(line_buffer, "D");	// ak sa po�adovan� ��slo rovn� 13 vytla� p�smeno D
			break;
		case (14) :
			strfcat(line_buffer, "E");	// ak sa po�adovan� ��slo rovn� 14 vytla� p�smeno E
			break;
		case (15) :
			strfcat(line_buffer, "F");	// ak sa po�adovan� ��slo rovn� 15 vytla� p�smeno F
			break;
		default :
			strfcat(line_buffer, "%d", number);	// v opa�nom pr�pade vytla� zodpovedaj�ce ��slo
	}
}

void print_byte(unsigned char byte, const char symbol, char* line_buffer) {		// funkcia vytla�� konkr�tny bajt, argument symbol sl��i ako rozde�ova� medzi jednotliv�mi bajtmi
	short mask = 240;		// maska horn�ch 4 bitov, bitovo = 1111 0000
	short high = (mask & byte) >> 4;	// vypo��tanie horn�ch 4 bitov
	short low = 15 & byte;	// vypo��tanie doln�ch 4 bitov
	print_hex(high, line_buffer);	// vytla�enie horn�ch 4 bitov v hexadecim�lnom tvare
	print_hex(low, line_buffer);		// vytla�enie doln�ch 4 bitov v hexadecim�lnom tvare
	strfcat(line_buffer, "%c", symbol);	// vytla�enie po�adovan�ho znaku z argumentov
}

void print_mac(char type, unsigned char* mac_address, char* line_buffer) {		// funkcia vytla�� mac adresu na obrazovku
	short i = 0;		// inicializ�cia pomocnej premennej, ktor� posl��i pre cyklus
	if (type==0) strfcat(line_buffer, "Source MAC --> ");		// ak sa typ argumentu rovn� nule, tak sa bude tla�i� zdrojov� mac adresa
	else if (type==1) strfcat(line_buffer, "Destination MAC --> ");	// v opa�nom pr�pade sa bude tla�i� cielov� mac adresa
	for (i = 0; i < 6; i++) {	// cyklus
		if (i==5) print_byte(mac_address[i], '\0', line_buffer); 	// ak sa jedn� o vytla�enie posledn�ho bajtu, tak za mac adresov sa vytla�� pr�dny znak
		else print_byte(mac_address[i], ':', line_buffer);	// v opa�nom pr�pade za koncom bajtu sa vytla�� znak :
	}
	if (type != 2) strfcat(line_buffer, "\n");	// posunutie na nov� riadok
}

void print_frame(int start, unsigned char* buffer, int frame_length, char* line_buffer) {		// funkcia vytla�� cel� r�mec pod�a za�iatku r�mca a celkovej d�ky r�mca
	int i = 0;		// inicializ�cia pomocnej premennej
	short byte_counter = 0;		// inicializ�cia premennej na po��tanie bajtov
	
	for (i = start; i < start + frame_length; i++) {	// cyklus, ktor� bude tla�i� jednotliv� bajty
		if (byte_counter == 8) strfcat(line_buffer, " ");		// ak sa po��tadlo bajtov rovn� 8, tak vytla� medzeru
		if (byte_counter == 16) {		// ak sa po��tadlo bajtov rovn� 16
			strfcat(line_buffer, "\n");		// prejdi na nov� riadok
			byte_counter = 0;	// natav po��tadlo bajtov na 0
		}
		print_byte(buffer[i], ' ', line_buffer);		// vytla� bajt na pozici� i
		byte_counter ++;	// inkrementuj po��tadlo bajtov
	}
	strfcat(line_buffer, "\n\n");		// prejdi na nov� riadok
}

unsigned short cut_type(int start, unsigned char* buffer) {		// funkcia vystrihne z buffera typ ��slo, ktor� bude pou��t� ako typ protokolu
	unsigned short result = 0;		// inicializ�cia n�vratovej hodnoty
	result = (buffer[start] << 8) + buffer[start + 1];	// vypo��tanie n�vratovej hodnoty z ��sel z buffera
	return result;	// n�vratov� hodnota predstavuje ��slo, ktor� nesk�r bude ozna�ova� typ protokolu
}

int str_to_int(const char* string) {	// funkcia prevedie string na celo��seln� hodnotu resp. integer
	int i = 0;		// inicializ�cia pomocnej premennej
	int result = 0;		// inicializ�cia n�vratovej hodnoty
	while (string[i]!='\n') {	// cyklus, ktor� postupne prech�dza string a konvertuje string na cel� ��slo
		result *= 10; 	// n�sobenie n�vratovej hodnoty desiatimi
		result += (string[i] - 48);		// pripo��tanie ��selnej hodnoty zo stringu
		i++;		// inkrement�cia pomocnej premennej
	}
	return result;	// n�vratov� hodnota je poskladan� cel� ��slo (int)
}

int get_ethernet_IEEE() {		// funkcia vr�ti cel� ��slo, ktor� predstavuje hranicu medzi ethernet II a IEEE
	int result = 0;		// inicializ�cia n�vratovej hodnoty
	char* line = (char*) malloc(80 * sizeof(char));		// inicializ�cia buffera, ktor� bude ��ta� zo s�boru riadky	
	FILE* file = fopen(CONSTANTS_FILE, "r");		// otvorenie s�bora Constants.txt na ��tanie
	while (fgets(line, 80, file)) {		// pokia� sa d� �ita� zo s�boru
		if ((strcmp(line, "__ETHERNET IEEE__\n")) == 0) {	// porovnaj pre��tan� riadok s dan�m stringom
			fgets(line, sizeof(line), file);	// ak sa rovnaj� pre��taj �al�� riadok, kde sa nach�dza dan� ��slo
			result = str_to_int(line);	 // konvertuj ��slo zo stringu do int-u
			break;	//ukon�i cyklus
		}
	}
	
	free(line);		// uvo�nenie pam�ti
	fclose(file);	// zatvorenie s�boru
	return result;	// n�vratov� hodnota je cel� ��slo pre�tan� zo s�boru
}

unsigned short cut_protocol_number(char* line, char* string) {		// funkcia vystrihne z pola line ��slo protokolu
	int i = 0;		// inicializ�cia pomocnej premennej pri cykloch
	unsigned short result = 0;		// inicializ�cia n�vratovej hodnoty
	while (line[i] != ' ') {	// za�iatok cyklu, k�m sa znak na pozici� i nerovn� medzere tak
		if (line[i] == '_' || line[i] == '\n') return 0; // ak sa rovn� �pecialnym znakom ukon�i funkciu s n�vratovou hodnotou 0
		result *= 10;	// vyn�sob v�sledok 10
		result += (line[i] - 48);	// pripo��taj ��slen� hodnotu na poz�ci� i
		i++;		// inkrement pomocnej premennej
	}
	
	i++;	// inkrement pomocnej premennej
	
	int k = 0;		// inicializ�cia pomocnej premennej k
	while (line[i] != '\n') {	// za�iatok cyklu, k�m sa znak na pozici� nerovn� ukon�eniu riadku
		string[k] = line[i];	// do pomocn�ho stringu zap� meno protokolu
		i++;	// inkrementuj pomocn� premenn� i
		k++;	// inkrementuj pomocn� premenn� k
	}
	string[k] = '\0';	// na koniec pomocn�ho stringu treba zap�sa� ukon�ovac� znak
	return result;	// n�vratov� hodnota je ��slo protokolu na��tan�ho zo s�boru
}

char* get_protocol_name(unsigned short type) {		// funkcia otvor� s�bor a pod�a parametru type vr�ti n�zov protokolu
	char* result_string = (char*) malloc(15 * sizeof(char));	// inicializ�cia stringu resp. pola znakov
	char* line = (char*) malloc(80 * sizeof(char));		// inicializ�cia buffera, ktor� bude ��ta� zo s�boru riadky
	FILE* file = fopen(CONSTANTS_FILE, "r");	// otvorenie s�bora Constants.txt na ��tanie
	
	while (fgets(line, 80, file)) {		// pokia� sa d� �ita� zo s�boru
		if (type == cut_protocol_number(line, result_string)) break;	// porovnaj argument type a ��slo protokolu, ak sa rovanj� ukon�i cyklus
		result_string[0] = '\0';	// ak sa nerovnaj� vynuluj string
	}
	
	fclose(file);	// zatvorenie s�boru
	free(line);		// uvolnenie pam�ti
	return result_string;	// n�vratov� hodnota je n�zov protokolu, ktor� sp��a podmienky
}

int write_in_string(unsigned char number, char* ip_string, int length) {	// funkcia zap�e po�adovan� ��slo do ip_stringu
	if (number == 0) {	// ak sa argument rovn� nule
		ip_string[length] = '0';	// zap� nulu do stringu
		length++;	// inkrementuj d�ku stringu
		return length;		// vr� d�ku stringu
	}
	
	short temp_number = 0;	// inicializ�cia pomocnej premennej
	short number_length = 0;	// inicializ�cia pomocnej premennej
	
	while (number != 0) {	// k�m sa ��slo nerovn� nule
		temp_number *= 10;		// vyn�sob pomocn� �islo desiatimi
		temp_number += (number % 10);	// pripo��taj k pomocn�mu ��slu zvy�ok po delen� desiatimi
		number = number / 10;	// delenie ��sla desiatimi
		number_length++;	// inkrement�cia d�ky ��sla
	}
	
	while (number_length != 0) {	// k�m d�ka ��sla sa nerovn� nule
		ip_string[length] = (temp_number % 10) + 48;	// pridaj zvy�ok po delen� 10 do stringu
		length++;	// inkrementuj d�ku stringu
		temp_number /= 10;	// vyde� pomcon� ��slo desiatimi
		number_length--;	// dekrementuj d�ku ��sla
	}
	
	return length;	// n�vratov� hodnota je d�ka stringu
}

char* get_ip(int start, unsigned char* buffer) {		// funkcia vr�ti string s ip adresou na z�klade buffera a argumentu start
	char* ip_string = (char*) malloc(16 * sizeof(char));	// alok�cia stringu pre ip adresu
	int i = 0;	// inicializ�cia pomocnej premennej
	int ip_string_len = 0;		// inicializ�cia d�ky ip stringu
	for (i = 0; i < 4; i++) {	// for cyklus, ktor� sa bude opakova� 4x
		ip_string_len = write_in_string(buffer[start+i], ip_string, ip_string_len);	// zap�sanie ��sla z buffera do ip_stringu
		if (i < 3) ip_string[ip_string_len] = '.';	// ak premenn� i je men�ia ako tri zap� do stringu aj bodku
		ip_string_len++;	// inkrement�cia d�ky stringu
	}
	ip_string[ip_string_len-1] = '\0';	// na koniec ip stringu zap� ukon�ovac� znak
	return ip_string;	// n�vratov� hodnota je string s ip adresou z buffera a posunu
}

#define FIN 1
#define SYN 2
#define RST 4
#define PSH 8
#define ACK 16
void print_tcp_flags(unsigned char tcp_flags, char* line_buffer) {		// funckia vytla�� na z�klade parametrov v�etky flagy tcp protokolu
	if (tcp_flags & FIN) strfcat(line_buffer, " [FIN]");
	if (tcp_flags & SYN) strfcat(line_buffer, " [SYN]");
	if (tcp_flags & RST) strfcat(line_buffer, " [RST]");
	if (tcp_flags & PSH) strfcat(line_buffer, " [PSH]");
	if (tcp_flags & ACK) strfcat(line_buffer, " [ACK]");
	
	strfcat(line_buffer, "\n");	// na konci sa vytla�� znak nov�ho riadku
}

void print_tcp(int start, unsigned char* buffer, char* line_buffer) {		// funkcia vytla�� na z�klade ��siel portov pr�slu�n� vnoren� tcp protokoly
	unsigned short source_port = (short) (buffer[start] << 8) + buffer[start + 1];		// inicializ�cia a nastavenie zdrojv�ho portu
	unsigned short destination_port = (short) (buffer[start + 2] << 8) + buffer[start + 3];	// inicializ�cia a nastavenie cielov�ho portu
	char* protocol_name_src = get_protocol_name(source_port);	// priradenie n�zvu protokolu pod�a ��sla zdrojov�ho portu
	char* protocol_name_dst = get_protocol_name(destination_port);	// priradenie n�zvu protokolu pod�a ��sla cielov�ho portu
	
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
	
	free(protocol_name_src);	// uvo�nenie pam�ti
	free(protocol_name_dst);	// uvo�nenie pam�ti
	strfcat(line_buffer, "Source Port --> %d\n", source_port);	// vytla�enie ��sla zdrojov�ho portu
	strfcat(line_buffer, "Destination Port --> %d\n", destination_port);	// vytla�enie ��sla cie�ov�ho portu
}

void print_udp(int start, unsigned char* buffer, char* line_buffer) {	// funkcia vytla�� na z�klade ��siel portov pr�slu�n� vnoren� udp protokoly
	unsigned short source_port = (short) (buffer[start] << 8) + buffer[start + 1];		// inicializ�cia a nastavenie zdrojv�ho portu
	unsigned short destination_port = (short) (buffer[start + 2] << 8) + buffer[start + 3];		// inicializ�cia a nastavenie cielov�ho portu
	char* protocol_name_src = get_protocol_name(source_port);		// priradenie n�zvu protokolu pod�a ��sla zdrojov�ho portu
	char* protocol_name_dst = get_protocol_name(destination_port);		// priradenie n�zvu protokolu pod�a ��sla cielov�ho portu
	
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
	
	free(protocol_name_src);	// uvo�nenie pam�ti
	free(protocol_name_dst);	// uvo�nenie pam�ti
	strfcat(line_buffer, "Source Port --> %d\n", source_port);		// vytla�enie ��sla zdrojov�ho portu
	strfcat(line_buffer, "Destination Port --> %d\n", destination_port);		// vytla�enie ��sla cie�ov�ho portu
}

void print_icmp(int start, unsigned char* buffer, char* line_buffer) {		// funkcia vytla�� podrobnosti o protokole ICMP
	strfcat(line_buffer, " - Type --> ");		// vytla�enie textu
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
	strfcat(line_buffer, "\n");		// vytla�enie ukon�ovacieho znaku
}

void print_ethernet_ip_protocol(int start, unsigned char* buffer, struct List** ip_list, char* line_buffer) {	// funkcia vytla�� podrobnosti o IP pr�padne aj vnoren� protokoly pod IP
	char ip_info = buffer[start];		// nastavenie premennej ip info
	char ip_info_high = (ip_info >> 4) & 15;		// osamostatnenie horn�ch 4 bitov
	char ip_info_low = ip_info & 15;		// osamostatnenie doln�ch 4 bitov
	if (ip_info_high == 4) {
		strfcat(line_buffer, "\nIPv4 (IHL %d)\n", ip_info_low);		// vyp�sanie inform�ci� o IPv4
	}
	strfcat(line_buffer, "Source IP --> %s\n", get_ip(start + 12, buffer));		// vyp�sanie zdrojovej ip adresy
	strfcat(line_buffer, "Destination IP --> %s\n", get_ip(start + 12 + 4, buffer));	// vyp�sanie cielovej ip adresy
	
	*ip_list = add_ip_address_to_list(convert_ip(get_ip(start+ 12, buffer)), *ip_list);		// pridanie adresy to listu ip adries
	
	short protocol_type = (short) buffer[start + 9];		// premenn� pre ��slo protokolu
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

int analyze(char* path, char filter, FILE* output) {		// funkcia analyzuje jednotliv� r�mce v s�bore .pcap
	
	unsigned char* line_buffer = (char*) malloc((6*4096)*sizeof(char));
	line_buffer[0] = '\0';
 	
	int temp_int = get_ethernet_IEEE();		// inicializ�cia a nastavenie pomocnej premennej
	
	
	FILE *fileptr;		// inicializ�cia smern�ka
	unsigned char *buffer;		// inicializ�cia buffera
	long filelen;		// inicializ�cia premennej d�ky s�boru

	fileptr = fopen(path, "rb");  	// otvorenie s�boru ako read byte
	fseek(fileptr, 0, SEEK_END);	// prejdenie na koniec s�boru          
	filelen = ftell(fileptr);        // nastavenie d�ky s�boru     
	rewind(fileptr);             // n�vrat na za�iatok s�boru         

	buffer = (unsigned char *) malloc(filelen * sizeof(unsigned char)); 	// buffer pre bajty zo s�boru
	fread(buffer, filelen, 1, fileptr); 		// na��taj s�bor do buffera
	fclose(fileptr); 	// zatvor s�bor
	
	struct List* ip_list = NULL;		// inicializ�cia sp�jan�ho zoznamu s ip adresami
		
	int i = 32;			// inicializ�cia pomocnej premennej
	int frame_number = 1;		// inicializ�cia premennej, ktor� ozna�uje po�et r�mcov
	int frame_length = 0;		// inicializ�cia premennej, ktor� ozna�uje ve�kos� r�mca
	unsigned char* destination_mac_address = NULL;		//inicializ�cia premennej pre cie�ov� mac adresu
	unsigned char* source_mac_address = NULL;		// inicializ�cia premennej pre zdrojov� mac adresu
	
	unsigned short type = 0;		// inicializ�cie premennej pre typ protokolu
	char* ethertype;	// inicializ�cia premennej pre stringov� typ protokolu
	
	while (i < filelen) {		// cyklus pre vyp�sanie v�etk�ch r�mcov
		frame_length = build_frame_length(buffer[i], buffer[i+1], buffer[i+2], buffer[i+3]);	// vytvorenie d�ky r�mca
		strfcat(line_buffer, "-----------------------------------------------------\n");		// vytla�enie odde�ova�a
		strfcat(line_buffer, "Frame Number --> %d\nFrame length available to pcap --> %d\n", frame_number, frame_length);		// vytla�enie d�ky r�mca
		if (frame_length <= 60) strfcat(line_buffer, "Frame length sent by medium --> 64\n\n");		// vytla�enie d�ky r�mca
		else strfcat(line_buffer, "Frame length sent by medium --> %d\n\n", frame_length + 4);		// vytla�enie d�ky r�mca
		
		destination_mac_address = cut_mac_address(i+8, buffer);		// nastavenie cie�ovej adresy
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
			print_mac(0, source_mac_address, line_buffer);		// vytla�enie zdrojovej mac adresy
			print_mac(1, destination_mac_address, line_buffer);	// vytla�enie cielovej mac adresy
		}
		
		strfcat(line_buffer, "\n");
		print_frame(i+8, buffer, frame_length, line_buffer);		// vytla�enie cel�ho ramca
		i += frame_length + 16;
		frame_number++;
		strfcat(line_buffer, "\n");
		free(destination_mac_address);		// uvo�nenie pam�te
		free(source_mac_address);		// uvo�nenie pam�te
		
		// n�sledn� if-else block sa star� o vyp�sanie konkr�tneho filtra
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
	free(line_buffer);		// uvo�nenie pam�te
	
	
	if (filter == 0) {
		fprintf(output, "-----------------------------------------------------\n");		// vytla�enie odde�ova�a
		unsigned int max_count = 0;		// inicializ�cia premennej po��tadla max�m
		struct List* temp = ip_list;	// inicializ�cia a nastavenie pomocn�ho smern�ka
		unsigned int maximum = ip_list->count;		// inicializ�cia a nastavenie maxima
		fprintf(output, "Source IPv4 Addresses	Count\n");		// informa�n� spr�va
		while (temp != NULL) {		// prechod cel�m sp�jan�m zoznamom a vytla�enie jednotliv�ch ip adries s pr�slu�n�mi po�etnos�ami
			fprintf(output, "%d.%d.%d.%d		%d\n", (temp->ip_address >> 24) & 255, (temp->ip_address >> 16) & 255, 
				(temp->ip_address >> 8) & 255, temp->ip_address & 255, temp->count);
			if (temp->count > maximum) {
				maximum = temp->count;
				max_count = 0;
			}
			if (temp->count == maximum) max_count++;
			temp = temp->next;
		}
	
		temp = ip_list; // vytla�enie najpo�etnej��ch ip adries/ ip adresy
		if (max_count > 1) fprintf(output, "\nHighest number of packets %d was sent by these IP addresses:\n", maximum);
		else if (max_count == 1) fprintf(output, "\nHighest number of packets %d was sent by this IP address:\n", maximum);
		while (temp != NULL) {
			if (temp->count == maximum) fprintf(output, "%d.%d.%d.%d\n", (temp->ip_address >> 24) & 255, (temp->ip_address >> 16) & 255, 
			(temp->ip_address >> 8) & 255, temp->ip_address & 255);
			temp = temp->next;
		}
	}

	
	
	
	free(buffer);	// uvo�nenie pam�ti
	free(ip_list);	// uvo�nenie pam�ti
	return 0;
}

struct Cmd* decode(char* buffer) {		// funkcia na z�klade pou��vate�sk�ho vstupu vo form�te string, vyparsuje dan� string a prerob� ho do �trukt�ry Cmd
	struct Cmd* result = (struct Cmd*) malloc(sizeof(struct Cmd));	// inicializ�cia smern�ka na Cmd
	result->path[0] = '\0';		// inicializ�cia jednotliv�ch premenn�ch
	result->filename[0] = '\0';
	result->redirect = 0;
	result->filter = 0;
	char filter[10];
	int i = 0;
	
	
	
	while (buffer[i] != ' ') {	// naplnenie premennej path (abosolutn� cesta k input s�boru)	
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
	if (buffer[i] == '-') {		//naplnenie premennej filter, pod�a �elan�ho protokolu
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
	if (buffer[i] == '>' && buffer[i+1] == '>'){ //naplnenie premennej filename (output file pre v�pisy r�mcov)
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
	
	
	return result;		// n�vratov� hodnota je vytvoren� smern�k, ktor� bude naplnen� potrebn�mi d�tami
}


int main() {
	char* command = (char*) malloc(150 * sizeof(char));			//alok�cia pam�te pre pr�kaz od pou��vate�a	
	struct Cmd* scommand = NULL;								//inicializ�cia smern�ka pre vyparsovan� pr�kaz
	
	printf("Enter Command or valid Path to your .pcap file >> ");
	while (scanf("%[^\n]%*c", command)) {						// naskenuj vstup od pou��vate�a
		if ((strcmp((const char*) command,"end")) == 0) break;		//ak pou��vate� zadal pr�kaz "end" ukon�i program
		else if ((strcmp((const char*) command,"help")) == 0) {		//ak pou��vate� zadal pr�kaz "help" vyp� help menu
			printf("Enter Path to your .pcap file to run the program\n\tType '>> filename' after your Path to redirect output to your file (.txt format)\n\tType -PROTOCOL_NAME after your Path to filter the frames\n");
			printf("----------------------------------------------\nType 'end' to terminate the program\n");
		}
		else {			//spracovanie pr�kazu a n�sledn� anal�za r�mcov
			scommand = decode(command);		// funkcia, ktor� vyparsuje pr�kaz a premen� ho na vhodnej�iu �trukt�ru
			if (scommand->redirect == 0) analyze(scommand->path, scommand->filter, stdout);		// ak sa redirect nenastavil na 1 tak vyp� r�mce na �tandardn� v�stup
			else {		// v opa�nom pr�pade otvor output file a nakop�ruj jednotliv� r�mce do�ho
				printf("\nOpening .txt file %s\n", scommand->filename);	
				FILE* file = fopen(scommand->filename, "w");
				printf("Analyzing ...\n");
				analyze(scommand->path, scommand->filter, file);
				printf("Closing .txt file %s\n", scommand->filename);
				fclose(file);		// zatvorenie s�boru
			}
			free(scommand);		// uvo�nenie pam�ti
			printf("\nDone!\n\n");	// inform��n� spr�va, �e v�etky r�mce sa vyp�sali
		}
		printf("Enter Command or valid Path to your .pcap file >> ");		// spr�va pre pou��vate�a, �e m��e zada� �al�� pr�kaz
	}
	free(command);		// uvo�nenie pam�ti
	
	return 0;
}
