#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns.h"

#define NS_NODE 1
#define QUERY_NODE 2
#define CNAME_NODE 3
#define A_NODE 4

struct cache_entry
{
char name[255];
uint32_t ttl;
time_t recorded_time;
};

struct NS_cache_entry
{
char name[255];
uint32_t ttl;
time_t recorded_time;
struct NS_cache_entry * next;
char name_server[255];
struct sockaddr_storage ip_address;
};

struct CNAME_cache_entry
{
char name[255];
uint32_t ttl;
time_t recorded_time;
struct CNAME_cache_entry * next;
char canonical_name[255];
};

struct A_cache_entry
{
char name[255];
char address[255];
uint32_t ttl;
time_t recorded_time;
struct A_cache_entry * next;
struct sockaddr_storage ip_address;
};

struct NS_cache_entry * NS_cache_head = NULL; int NS_cache_size = 0;
struct CNAME_cache_entry * CNAME_cache_head = NULL; int CNAME_cache_size = 0;
struct A_cache_entry * A_cache_head = NULL; int A_cache_size = 0;

void add_ns_entry(char * name, char * authoritative_server, struct sockaddr_storage * ip_address, int ttl)
{
struct NS_cache_entry * entry = (struct NS_cache_entry *)malloc(sizeof(struct NS_cache_entry));
struct NS_cache_entry * current = NULL;
strcpy(entry->name, name);
strcpy(entry->name_server, authoritative_server);
entry->ip_address = *ip_address;
entry->ttl = ttl;
time(&(entry->recorded_time));
entry->next = NULL;
if(NS_cache_head != NULL)
{
for(struct NS_cache_entry * current = NS_cache_head; current->next != NULL; current = current->next);
current->next = entry;
}
else
{
NS_cache_head = entry;
}
NS_cache_size ++;
}

struct NS_cache_entry * fetch_NS_records(char * name)
{
struct NS_cache_entry * list = NULL;
for(struct NS_cache_entry * current = NS_cache_head; current != NULL; current = current->next)
{
if(strstr(current->name, name) != NULL)
{
struct NS_cache_entry * new_entry = (struct NS_cache_entry *)malloc(sizeof(struct NS_cache_entry));
*new_entry = *current;
new_entry->next = list;
list = new_entry;
}
}
return list;
}

void refresh_NS_cache()
{
time_t now;
time(&now);
int diff = 0;
struct NS_cache_entry * previous_entry;
for(struct NS_cache_entry * current = NS_cache_head; current != NULL; current = current->next)
{
diff = (int) difftime(now, current->recorded_time);
if(current->ttl < diff)
{
if(current == NS_cache_head)
    NS_cache_head = current->next;
else
    previous_entry->next = current->next;

NS_cache_size --;
}
previous_entry = current;
}
}

void add_CNAME_entry(char * name, char * canonical_name, int ttl)
{
struct CNAME_cache_entry * entry = (struct CNAME_cache_entry *)malloc(sizeof(struct CNAME_cache_entry));
strcpy(entry->name, name);
strcpy(entry->canonical_name, canonical_name);
entry->ttl = ttl;
time(&(entry->recorded_time)); 
entry->next = CNAME_cache_head;
CNAME_cache_head = entry;
CNAME_cache_size ++;
}

struct CNAME_cache_entry * fetch_CNAME_records(char * name)
{
struct CNAME_cache_entry * list = NULL;
for(struct CNAME_cache_entry * current = CNAME_cache_head; current->next != NULL; current = current->next)
{
if(strcmp(current->name, name) == 0)
{
struct CNAME_cache_entry * new_entry = (struct CNAME_cache_entry *)malloc(sizeof(struct CNAME_cache_entry));
*new_entry = *current;
new_entry->next = list;
list = new_entry;
}
}
return list;
}

void refresh_CNAME_cache()
{
time_t now;
time(&now);
int diff = 0;
struct CNAME_cache_entry * previous_entry;
for(struct CNAME_cache_entry * current = CNAME_cache_head; current != NULL; current = current->next)
{
diff = (int) difftime(now, current->recorded_time);
if(current->ttl < diff)
{
if(current == CNAME_cache_head)
    CNAME_cache_head = current->next;
else
    previous_entry->next = current->next;

CNAME_cache_size --;
}
previous_entry = current;
}
}

void add_A_entry(char * name, struct sockaddr_storage * address, int ttl)
{
char printbuf[INET6_ADDRSTRLEN];
if(address->ss_family == AF_INET)
    inet_ntop(AF_INET, (void *)&((struct sockaddr_in *)address)->sin_addr, printbuf, INET_ADDRSTRLEN);
else if(address->ss_family == AF_INET6)
    inet_ntop(AF_INET6, (void *)&((struct sockaddr_in6 *)address)->sin6_addr, printbuf, INET6_ADDRSTRLEN);
for(struct A_cache_entry * entry = A_cache_head; entry != NULL; entry = entry->next)
{
    if( (strcmp(entry->name, name) == 0) && (strcmp(entry->address, printbuf) ==0))
    {
        printf("Duplicate found \n");
        return;
    }
}

struct A_cache_entry * entry = (struct A_cache_entry *)malloc(sizeof(struct A_cache_entry));
strcpy(entry->name, name);
strcpy(entry->address, printbuf);
entry->ip_address = *address;
entry->ttl = ttl;
time(&(entry->recorded_time)); 
entry->next = A_cache_head;
A_cache_head = entry;
A_cache_size ++;
}

struct A_cache_entry * fetch_A_records(char * name)
{
struct A_cache_entry * list = NULL;
for(struct A_cache_entry * current = A_cache_head; current != NULL; current = current->next)
{
if(strcmp(current->name, name) == 0)
{
struct A_cache_entry * new_entry = (struct A_cache_entry *)malloc(sizeof(struct A_cache_entry));
*new_entry = *current;
new_entry->next = list;
list = new_entry;
}
}
return list;
}

void refresh_A_cache()
{
time_t now;
time(&now);
int diff = 0;
struct A_cache_entry * previous_entry;
for(struct A_cache_entry * current = A_cache_head; current != NULL; current = current->next)
{
diff = (int) difftime(now, current->recorded_time);
if(current->ttl < diff)
{
if(current == A_cache_head)
    A_cache_head = current->next;
else
    previous_entry->next = current->next;

A_cache_size --;
}
previous_entry = current;
}
}

void print_A_records()
{
printf("A RECORDS CACHED ENTRIES\n");
for(struct A_cache_entry * current = A_cache_head; current != NULL; current = current->next)
{
printf("%s\n",current->name);
}
}

//note should return all A and AAAA records
struct authserverrecord
{
char domain[255];
char server_name[255];
struct sockaddr_storage server_addr;
};

struct dns_query{
uint16_t query_id;
uint8_t request[500];
int request_size;
struct sockaddr_storage client_address;
struct dns_state_node * query_root;
struct dns_query * next;
};
struct dns_query * queries = NULL;

struct dns_state_node{
int type;
char name[255];
struct sockaddr_storage address;
struct dns_state_node * query_branch;
struct dns_state_node * next ;
struct dns_state_node * query_parent;
struct dns_state_node * parent ;
int is_complete;
uint16_t qtype;
};

struct dns_state_ns_node{
int type;
char name[255];
struct sockaddr_storage address;
struct dns_state_node * query_branch;
struct dns_state_node * next;
struct dns_state_node * query_parent;
struct dns_state_node * parent;
int is_complete;
uint16_t qtype;
struct dns_state_node * iterative_branch;
char ns_domain[255];
};




int print_dns_query_tree(struct dns_state_node * node, int recursion_level)
{
    struct dns_state_node * next_node;
    char client_ip[255];
    for(int i=0;i<recursion_level;i++)
        printf("\t");
    switch (node->type)
    {
    case QUERY_NODE:
        printf("Query: ");
        break;
    case NS_NODE:
        printf("NS: ");
        break;
    case A_NODE:
        printf("A: ");
        break;
    case CNAME_NODE:
        printf("CName: ");
        break;
    }
    printf("%s", node->name);
    if(node->address.ss_family == AF_INET)
        printf("<>%s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&node->address)->sin_addr), client_ip, INET_ADDRSTRLEN));
    else if(node->address.ss_family == AF_INET6)
        printf("<>%s\n", inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&node->address)->sin6_addr), client_ip, INET6_ADDRSTRLEN));
    else
        printf("\n");
        
    
    recursion_level ++;
    next_node = node->query_branch;
    while(next_node != NULL)
    {
    print_dns_query_tree(next_node, recursion_level);
    next_node = next_node->next;
    }
}


int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response, struct sockaddr_storage * nameservers, int nameserver_count);

typedef struct addrinfo saddrinfo;
typedef struct sockaddr_storage sss;
int root_server_count;
sss root_servers[255];
static int debug=0;


uint16_t extract_queried_url(uint8_t * request, char * url){
  struct dns_hdr * header = (struct dns_hdr *) request;
  uint8_t * answer_ptr = request + sizeof(struct dns_hdr);

  // now answer_ptr points at the first question.
  int question_count = ntohs(header->q_count);
  int answer_count = ntohs(header->a_count);
  int auth_count = ntohs(header->auth_count);
  int other_count = ntohs(header->other_count);


  if(debug)
    printf("in extract answer\n");
  // if we didn't get an answer, just quit
  

  // skip questions
  for(int q=0; q<question_count; q++){
    int size=from_dns_style(request, answer_ptr,url);
    answer_ptr+=size;
    uint16_t  type = htons(*(uint16_t*)answer_ptr);
    printf("Query type :%d\n", type);
    answer_ptr+=4;
    return type;
  }
return 0;
}

int construct_response(uint8_t * response, int max_response, char * queried_url, struct A_cache_entry * result_list, int query_id, uint16_t qtype)
{
    uint8_t * pointer = response;
    int host_name_size;
    char print_buff[50];
    memset(response, 0, max_response);
    struct dns_hdr * hdr = (struct dns_hdr*) response;
    hdr->id = htons(query_id);
    hdr->flags = htons(0x8000);
    hdr->q_count = htons(1);
    
    
    pointer += sizeof(struct dns_hdr);


     
  int name_len=to_dns_style(queried_url ,pointer);
  pointer += name_len; 
  // now the query type: A/AAAA or PTR. 
  uint16_t *type = (uint16_t*)(pointer);
  *type = htons(qtype);
  pointer += 2;
  //finally the class: INET
  uint16_t *class = (uint16_t*)(pointer);
  *class = htons(1);
  pointer += 2;
  
    int count = 0;
    for(struct A_cache_entry * entry = result_list; entry != NULL; entry = entry->next)
    {
    count ++;
    host_name_size = to_dns_style(entry->name, pointer);
    pointer += host_name_size;
    struct dns_rr * a_record_hdr = (struct dns_rr *)pointer;
    
    a_record_hdr->class = htons(DNS_CLASS_IN);
    a_record_hdr->ttl = htonl(entry->ttl);
    pointer += sizeof(struct dns_rr);
    struct sockaddr_storage * host_address = &(entry->ip_address);
    if(host_address->ss_family == AF_INET)
    {
        struct  in_addr * host_ip;
        a_record_hdr->type = htons(RECTYPE_A);
        a_record_hdr->datalen = htons(4);
        host_ip = (struct in_addr *)pointer;
        *host_ip =  ((struct sockaddr_in *)host_address)->sin_addr;
        pointer += sizeof(struct in_addr);
    }
    else if(host_address->ss_family == AF_INET6)
    {
        struct  in6_addr * host_ip6;
        a_record_hdr->type = htons(RECTYPE_AAAA);
        a_record_hdr->datalen = htons(16);
        host_ip6 = (struct in6_addr *)pointer;
        *host_ip6 =  ((struct sockaddr_in6 *)host_address)->sin6_addr;
        if(debug)
            printf("Extracted ip is: %s\n", inet_ntop(AF_INET6, host_ip6, print_buff, 255));
        pointer += sizeof(struct in6_addr);
    }
    }
    hdr->a_count = htons(count);
    return (pointer-response);
     
}


/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname,int qtype, uint16_t query_id) {
  memset(query,0,max_query);
  // does the hostname actually look like an IP address? If so, make
  // it a reverse lookup. 
  in_addr_t rev_addr=inet_addr(hostname);
  if(rev_addr!=INADDR_NONE) {
    static char reverse_name[255];		
    sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
        (rev_addr&0xff000000)>>24,
        (rev_addr&0xff0000)>>16,
        (rev_addr&0xff00)>>8,
        (rev_addr&0xff));
    hostname=reverse_name;
  }
  // first part of the query is a fixed size header
  struct dns_hdr *hdr = (struct dns_hdr*)query;
  // generate a random 16-bit number for session
  //uint16_t query_id = (uint16_t) (random() & 0xffff);
  hdr->id = htons(query_id);
  // set header flags to request recursive query
  hdr->flags = htons(0x0100);	
  // 1 question, no answers or other records
  hdr->q_count=htons(1);
  // add the name
  int query_len = sizeof(struct dns_hdr); 
  int name_len=to_dns_style(hostname,query+query_len);
  query_len += name_len; 
  // now the query type: A/AAAA or PTR. 
  uint16_t *type = (uint16_t*)(query+query_len);
  if(rev_addr!=INADDR_NONE)
  {
    *type = htons(12);
  }
  else
  {
    *type = htons(qtype);
  }
  query_len+=2;
  //finally the class: INET
  uint16_t *class = (uint16_t*)(query+query_len);
  *class = htons(1);
  query_len += 2;
  return query_len;	
}


int process_request(uint8_t * message, int message_size, struct sockaddr_storage * client_address, 
                          uint8_t * request, int request_buff_size, struct sockaddr_storage * host_addr)
{
    print_A_records();
    struct dns_hdr * message_header = (struct dns_hdr *)message;
    struct dns_query * query;
    struct dns_state_node * ns_node = NULL;
    struct dns_state_node * root_node;
    struct dns_state_node * current_node = NULL;
    struct dns_state_node * node_to_be_processed = NULL;
    struct A_cache_entry * result_list_head = NULL;
    char url[255];
    //int query_id = response_header->id;
    if((htons(message_header->flags) & 0x8000) == 0)
    {
        
        if(debug)
            printf("Got query with id:%d\n", htons(message_header->id));
        uint16_t qtype = extract_queried_url(message, url);
        
        query = (struct dns_query *)malloc(sizeof(struct dns_query));
        memcpy(&(query->request), message, message_size);
        query->query_id = (uint16_t) (random() & 0xffff);
        query->request_size = message_size; 
        query->client_address = *(client_address);
        root_node = (struct dns_state_node *)malloc(sizeof(struct dns_state_node));
        root_node->type = QUERY_NODE;
        root_node->qtype = extract_queried_url(message, root_node->name);
        memset((void *)&root_node->address, 0, sizeof(struct sockaddr_storage));
        root_node->query_branch = NULL;
        root_node->next = NULL;
        root_node->parent = NULL;
        root_node->query_parent = NULL;
        root_node->is_complete = 0;
        //root_node->iterative_branch = NULL;
        query->query_root = root_node;
        query->next = queries;
        queries = query;
        struct dns_state_node * previous_node = NULL;
        
        for(int i=0; i<root_server_count; i++)
        {
        ns_node = (struct dns_state_node *)malloc(sizeof(struct dns_state_ns_node));
        ns_node->type = NS_NODE;
        strcpy(ns_node->name, "root_server");
        ns_node->address = root_servers[i];
        ns_node->query_branch = NULL;
        ns_node->next = NULL;
        ns_node->parent = root_node;
        ns_node->query_parent = root_node;
        ns_node->is_complete = 0;
        if(previous_node == NULL)
        {
        root_node->query_branch = (struct dns_state_node *) ns_node;
        }
        else
        {
        previous_node->next = (struct dns_state_node *) ns_node;
        }
        previous_node = (struct dns_state_node *) ns_node;
        }   
    
    message_header = (struct dns_hdr *)query->request;
    int query_id = query->query_id;
    node_to_be_processed = root_node->query_branch;
    *host_addr = node_to_be_processed->address;
    
    if(debug)
    {
        printf("TREE STRUCTURE INITIAL:\n");
        print_dns_query_tree(queries->query_root, 0);
    } 
    return construct_query(request, request_buff_size, root_node->name, 255, htons(query_id)); 
    
    }
    else
    {
        int found_flag = 0;
        struct dns_state_node * list_head = NULL;
        struct dns_query * previous_query = NULL;
        uint8_t * pointer = (uint8_t *)message;
        pointer += sizeof(struct dns_hdr);
        if(debug)
            printf("Searching for query id: %d\n", htons(message_header->id));
        for(query = queries; query != NULL; query = query->next)
        {
        struct dns_hdr * initial_request_header = (struct dns_hdr *)&(query->request);
        
        if(htons(message_header->id) == query->query_id)
        {
        found_flag = 1;
        if(debug)
            printf("Query id: %d matched\n", htons(initial_request_header->id));
        
        ns_node = query->query_root;
        while(ns_node->is_complete != 0 || ns_node->query_branch != NULL)
        {
        if(ns_node->is_complete != 0)
            ns_node = ns_node->next;
        else if(ns_node->query_branch != NULL)
            ns_node = ns_node->query_branch;
        
        }
        
        
        int question_count = ntohs(message_header->q_count);
        int answer_count = ntohs(message_header->a_count);
        int auth_count = ntohs(message_header->auth_count);
        int other_count = ntohs(message_header->other_count);


  
        if (answer_count != 0 ){
           if(debug)
               printf("Answer found\n");
        }

        // skip questions
        for(int q=0; q<question_count; q++){
        char string_name[255];
        memset(string_name,0,255);
        int size=from_dns_style(message, pointer,string_name);
        pointer+=size;
        pointer+=4;
        }

        if(debug)
            printf("Got %d+%d+%d=%d resource records total.\n",answer_count,auth_count,other_count,answer_count+auth_count+other_count);
        if(answer_count+auth_count+other_count>50){
            printf("ERROR: got a corrupt packet\n");
            return -1;
        }

        /*
         * accumulate authoritative nameservers to a list so we can recurse through them
         */
        for(int a=0; a<answer_count+auth_count+other_count;a++)
        {
        // first the name this answer is referring to
        char string_name[255];
        int dnsnamelen=from_dns_style(message, pointer, string_name);
        pointer += dnsnamelen;

        // then fixed part of the RR record
        struct dns_rr* rr = (struct dns_rr*)pointer;
        pointer+=sizeof(struct dns_rr);

        //A record
        if(htons(rr->type)==RECTYPE_A)
        {
        if(debug)
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntoa(*((struct in_addr *)pointer)));
        struct sockaddr_storage  address_for_caching;
        struct sockaddr_in * address_pointer = (struct sockaddr_in *)&address_for_caching;
        address_pointer->sin_family = AF_INET;
        address_pointer->sin_addr = *((struct in_addr *)pointer);
        
        //if it's in the answer section, then we got our answer
        if(a<answer_count)
        {
        
        if(strcmp(string_name, ns_node->query_parent->name) == 0)
        {
            
            struct dns_state_node * query_node;
            if(ns_node->type == QUERY_NODE ||ns_node->type == CNAME_NODE)
                query_node = ns_node;
            else if(ns_node->type == NS_NODE)
                query_node = ns_node->query_parent;
            refresh_A_cache();
            if(A_cache_size < 200)
                add_A_entry(query->query_root->name, &(query->query_root->address), htonl(rr->ttl));

            while(query_node != NULL)
            {
            struct sockaddr_in * result = (struct sockaddr_in *)&(query_node->address);
            ((struct sockaddr_in*)result)->sin_family = AF_INET;
            ((struct sockaddr_in*)result)->sin_addr = *((struct in_addr *)pointer);
            query_node->is_complete = 1;
            query_node = query_node->query_parent;
            }
            
            
            
            char queried_url[255];
            extract_queried_url(query->request, queried_url);
            *host_addr = query->client_address;
            struct A_cache_entry * result_entry = (struct A_cache_entry *)malloc(sizeof(struct A_cache_entry));
            strcpy(result_entry->name, queried_url); 
            result_entry->ip_address = query->query_root->address;
            result_entry->ttl = htonl(rr->ttl);
            result_entry->next = result_list_head;
            result_list_head = result_entry;
            //return construct_response(request, request_buff_size, queried_url, &(query->query_root->address), 
            //    htons(initial_request_header->id), rr->ttl); 
        }
        }
        else
        {
        for(current_node = list_head; current_node!=NULL && (strcmp(current_node->name, string_name) !=0); current_node = current_node->next);
        if(current_node != NULL){
            ((struct sockaddr_in *)(&(current_node->address)))->sin_addr = *((struct in_addr *)pointer);
            ((struct sockaddr_in *)(&(current_node->address)))->sin_port = htons(53);
            current_node->address.ss_family = AF_INET;
        }
        }
        }

    
        else if(htons(rr->type)==RECTYPE_NS)
        {
        char ns_string[255];
        int ns_len=from_dns_style(message, pointer, ns_string);
        if(debug)
            printf("The name %s is also known as %s.\n",				
                string_name, ns_string);
        
        struct dns_state_ns_node * new_ns_node = (struct dns_state_ns_node *)malloc(sizeof(struct dns_state_ns_node));
        new_ns_node->type = NS_NODE;
        strcpy(new_ns_node->name, ns_string);
        memset(&(new_ns_node->address), 0, sizeof(sss));
        new_ns_node->query_branch = NULL;
        new_ns_node->parent = ns_node;
        new_ns_node->next = NULL;
        if(ns_node->type == CNAME_NODE || ns_node->type == QUERY_NODE)
            new_ns_node->query_parent = ns_node;
        else
            new_ns_node->query_parent = ns_node->query_parent;
        new_ns_node->is_complete = 0;
        new_ns_node->iterative_branch = NULL;
        strcpy(new_ns_node->ns_domain, ns_string);

        
        if(list_head == NULL)
            list_head = (struct dns_state_node *) new_ns_node;
        else{
            for(current_node = list_head;current_node->next != NULL;current_node = current_node->next);
            current_node->next = (struct dns_state_node *)new_ns_node;
        }
        
        }
        //CNAME record
        else if(htons(rr->type)==RECTYPE_CNAME)
        {
        char ns_string[255];
        int ns_len=from_dns_style(message, pointer, ns_string);
        if(debug)
            printf("The name %s is also known as %s.\n",				
                string_name, ns_string);
        if(strcmp(string_name, ns_node->query_parent->name) == 0)
        {
            struct dns_state_node * new_ns_node = (struct dns_state_node *)malloc(sizeof(struct dns_state_ns_node));
            new_ns_node->type = CNAME_NODE;
            strcpy(new_ns_node->name, ns_string);
            memset(&(new_ns_node->address), 0, sizeof(sss));
            new_ns_node->query_branch = NULL;
            new_ns_node->parent = ns_node;
            new_ns_node->next = NULL;
            if(ns_node->type == CNAME_NODE || ns_node->type == QUERY_NODE)
                new_ns_node->query_parent = ns_node;
            else
                new_ns_node->query_parent = ns_node->query_parent;
            new_ns_node->next = list_head;
            list_head = new_ns_node;
        }
        struct dns_state_node * previous_node = NULL;
        
        for(int i=0; i<root_server_count; i++)
        {
        struct dns_state_node * new_ns_node = (struct dns_state_node *)malloc(sizeof(struct dns_state_ns_node));
        new_ns_node->type = NS_NODE;
        strcpy(new_ns_node->name, "root_server");
        new_ns_node->address = root_servers[i];
        new_ns_node->query_branch = NULL;
        new_ns_node->next = NULL;
        new_ns_node->parent = list_head;
        new_ns_node->query_parent = list_head;
        new_ns_node->is_complete = 0;
        if(previous_node == NULL)
        {
        list_head->query_branch = (struct dns_state_node *) new_ns_node;
        }
        else
        {
        previous_node->next = (struct dns_state_node *) new_ns_node;
        }
        previous_node = (struct dns_state_node *) new_ns_node;
        }
        }
        // AAAA record
        else if(htons(rr->type)==RECTYPE_AAAA)	
        {
        if(debug)
        {
            char printbuf[INET6_ADDRSTRLEN];	
            printf("The name %s resolves to IP addr: %s\n",
                string_name,
                    inet_ntop(AF_INET6, pointer, printbuf,INET6_ADDRSTRLEN));
        }

        if(a<answer_count)
        {
        
        if(strcmp(string_name, ns_node->query_parent->name) == 0)
        {
            

            struct dns_state_node * query_node;
            if(ns_node->type == QUERY_NODE ||ns_node->type == CNAME_NODE)
                query_node = ns_node;
            else if(ns_node->type == NS_NODE)
                query_node = ns_node->query_parent;
            while(query_node != NULL)
            {
            struct sockaddr_in6 * result = (struct sockaddr_in6 *)&(query_node->address);
            ((struct sockaddr_in6*)result)->sin6_family = AF_INET6;
            ((struct sockaddr_in6*)result)->sin6_addr = *((struct in6_addr *)pointer);
            ((struct sockaddr_in6*)result)->sin6_port = htons(53);
            query_node = query_node->query_parent;
            }
            refresh_A_cache();
            if(A_cache_size < 200)
                add_A_entry(query->query_root->name, &(query->query_root->address), htonl(rr->ttl));
            char queried_url[255];
            *host_addr = query->client_address;
            extract_queried_url(query->request, queried_url);
            struct A_cache_entry * result_entry = (struct A_cache_entry *)malloc(sizeof(struct A_cache_entry));
            strcpy(result_entry->name, queried_url); 
            result_entry->ip_address = query->query_root->address;
            result_entry->ttl = htonl(rr->ttl);
            result_entry->next = result_list_head;
            result_list_head = result_entry;
        }
        }
        else
        {
        for(current_node = list_head; current_node!=NULL && (strcmp(current_node->name, string_name) !=0); current_node = current_node->next);
        if(current_node != NULL){
            ((struct sockaddr_in6 *)(&(current_node->address)))->sin6_addr = *((struct in6_addr *)pointer);
            current_node->address.ss_family = AF_INET6;
        }
        }
      
      
        }
        else
        {
        if(debug)
            printf("got unknown record type %hu\n", htons(rr->type));
        }
        pointer+=htons(rr->datalen);
        }
        
        if(result_list_head != NULL)
        {
        if(previous_query == NULL)
        {
        queries = queries->next;
        }
        else
        {
        previous_query->next = query->next;
        }
        return construct_response(request, request_buff_size, url, result_list_head, 
                htons(initial_request_header->id), query->query_root->qtype);
        }
        
        if(list_head != NULL)
        {
        ns_node->query_branch = list_head;
        if(debug)
        {
        printf("TREE STRUCTURE:\n");
        print_dns_query_tree(queries->query_root, 0);
        } 
        if(list_head->type == CNAME_NODE)
        {
        *(host_addr) = list_head->address;
        return construct_query(request, request_buff_size, list_head->name, 255, query->query_id); 
        }
        else
        {
        *(host_addr) = list_head->address;
        return construct_query(request, request_buff_size, list_head->query_parent->name, 255, query->query_id); 
        }
        }
        else
        {
        ns_node->is_complete = 1;
        return -1;
        }
        }
        previous_query = query;
        }
        if(found_flag == 0){
            printf("Query not matched\n");
            return -1;
        }
   } 
   
}



int timeout_query(struct dns_query * query, uint8_t * request, int request_buff_size, struct sockaddr_storage * host_addr)
{
    struct dns_state_node * ns_node = query->query_root;
    struct dns_hdr * initial_request_struct = (struct dns_hdr *)query->request;
    while(ns_node->is_complete != 0 || ns_node->query_branch != NULL)
    {
    if(ns_node->is_complete != 0)
        ns_node = ns_node->next;
    else if(ns_node->query_branch != NULL)
        ns_node = ns_node->query_branch;
    
    }
    ns_node->is_complete = 1;
    while(ns_node->next == NULL && ns_node->parent != NULL)
    {
    ns_node->parent->is_complete = 1;
    ns_node = ns_node->parent;
    }
    if(ns_node->next != NULL)
    {
    ns_node = ns_node->next;
    if(ns_node->type == CNAME_NODE)
    {
    *(host_addr) = ns_node->address;
    return construct_query(request, request_buff_size, ns_node->name, 255, query->query_id); 
    }
    else
    {
    *(host_addr) = ns_node->address;
    return construct_query(request, request_buff_size, ns_node->query_parent->name, 255, query->query_id); 
    }
    
    }
    else
        return -1;
}
void usage() {
  printf("Usage: hw4 [-d] [-p port]\n\t-d: debug\n\t-p: port\n");
  exit(1);
}


/* returns: true if answer found, false if not.
 * side effect: on answer found, populate result with ip address.
 */
int extract_answer(uint8_t * response, sss * result){
  // parse the response to get our answer
  struct dns_hdr * header = (struct dns_hdr *) response;
  uint8_t * answer_ptr = response + sizeof(struct dns_hdr);

  memset(result,0,sizeof(sss));
  
  // now answer_ptr points at the first question.
  int question_count = ntohs(header->q_count);
  int answer_count = ntohs(header->a_count);
  int auth_count = ntohs(header->auth_count);
  int other_count = ntohs(header->other_count);


  if(debug)
    printf("in extract answer\n");
  // if we didn't get an answer, just quit
  if (answer_count == 0 ){
    return 0;
  }

  // skip questions
  for(int q=0; q<question_count; q++){
    char string_name[255];
    memset(string_name,0,255);
    int size=from_dns_style(response, answer_ptr,string_name);
    answer_ptr+=size;
    answer_ptr+=4;
  }

  if(debug)
    printf("Got %d+%d+%d=%d resource records total.\n",answer_count,auth_count,other_count,answer_count+auth_count+other_count);
  if(answer_count+auth_count+other_count>50){
    printf("ERROR: got a corrupt packet\n");
    return -1;
  }

  /*
   * accumulate authoritative nameservers to a list so we can recurse through them
   */
  for(int a=0; a<answer_count;a++)
  {
    // first the name this answer is referring to
    char string_name[255];
    int dnsnamelen=from_dns_style(response,answer_ptr,string_name);
    answer_ptr += dnsnamelen;

    // then fixed part of the RR record
    struct dns_rr* rr = (struct dns_rr*)answer_ptr;
    answer_ptr+=sizeof(struct dns_rr);

    //A record
    if(htons(rr->type)==RECTYPE_A)
    {
      if(debug)
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntoa(*((struct in_addr *)answer_ptr)));
      //if it's in the answer section, then we got our answer
      if(a<answer_count)
      {
        ((struct sockaddr_in*)result)->sin_family = AF_INET;
        ((struct sockaddr_in*)result)->sin_addr = *((struct in_addr *)answer_ptr);
        return 1;
      }
      
    }
    //CNAME record
    else if(htons(rr->type)==RECTYPE_CNAME)
    {
      char ns_string[255];
      int ns_len=from_dns_style(response,answer_ptr,ns_string);
      if(debug)
        printf("The name %s is also known as %s.\n",				
            string_name, ns_string);

    }
    // AAAA record
    else if(htons(rr->type)==RECTYPE_AAAA)	
    {
      if(debug)
      {
        char printbuf[INET6_ADDRSTRLEN];	
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntop(AF_INET6, answer_ptr, printbuf,INET6_ADDRSTRLEN));
      }
      ((struct sockaddr_in6*)result)->sin6_family = AF_INET6;
      ((struct sockaddr_in6*)result)->sin6_addr = *((struct in6_addr *)answer_ptr);
      return 1;
      
    }
    else
    {
      if(debug)
        printf("got unknown record type %hu\n", htons(rr->type));
    }
    answer_ptr+=htons(rr->datalen);
  }
  return 0;
}

// wrapper for inet_ntop that takes a sockaddr_storage as argument
const char * ss_ntop(struct sockaddr_storage * ss, char * dst, int dstlen)
{		  
  void * addr;
  if (ss->ss_family == AF_INET)
    addr = &(((struct sockaddr_in*)ss)->sin_addr);
  else if (ss->ss_family == AF_INET6)
    addr = &(((struct sockaddr_in6*)ss)->sin6_addr);
  else
  {
    if (debug)
      printf("error parsing ip address\n");
    return NULL;
  }
  return inet_ntop(ss->ss_family, addr, dst, dstlen);
}

/*
 * wrapper for inet_pton that detects a valid ipv4/ipv6 string and returns it in pointer to
 * sockaddr_storage dst
 *
 * return value is consistent with inet_pton
 */
int ss_pton(const char * src, void * dst){
  // try ipv4
  unsigned char buf[sizeof(struct in6_addr)];
  int r;
  r = inet_pton(AF_INET,src,buf);
  if (r == 1){
    char printbuf[INET6_ADDRSTRLEN];
    struct sockaddr_in6 * out = (struct sockaddr_in6*)dst;
    // for socket purposes, we need a v4-mapped ipv6 address
    unsigned char * mapped_dst = (void*)&out->sin6_addr;
    // take the first 4 bytes of buf and put them in the last 4
    // of the return value
    memcpy(mapped_dst+12,buf,4);
    // set the first 10 bytes to 0
    memset(mapped_dst,0,10);
    // set the next 2 bytes to 0xff
    memset(mapped_dst+10,0xff,2);
    out->sin6_family = AF_INET6;
    return 1;
  }
  r = inet_pton(AF_INET6,src,buf);
  if (r == 1){
    struct sockaddr_in6 * out = (struct sockaddr_in6*)dst;
    out->sin6_family = AF_INET6;
    out->sin6_addr = *((struct in6_addr*)buf);
    return 1;
  }
  return r;
}


void read_server_file() {
  root_server_count=0;
  char addr[25];

  FILE *f = fopen("root-servers.txt","r");
  while(fscanf(f," %s ",addr) > 0){
    ss_pton(addr,&root_servers[root_server_count++]);
    struct sockaddr_in6 * inet6 = (struct sockaddr_in6 *)&root_servers[root_server_count-1];
    inet6->sin6_port = htons(53);
    if(root_servers[root_server_count - 1].ss_family == AF_INET)
        printf("AF_INET\n");
    else if(root_servers[root_server_count - 1].ss_family == AF_INET6)
        printf("AF_INET6\n");
  }
}

/*

int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response, struct sockaddr_storage * nameservers, int nameserver_count)
{
  struct dns_hdr * request_header = (struct dns_hdr *) request;
  if(debug)
      printf("qury id:%d\n", ntohs(request_header->id));
  //Assume that we're getting no more than 20 NS responses
  char recd_ns_name[20][255];
  struct sockaddr_in6 * server_addr6;
  char queried_url[255];
  struct sockaddr_in * server_addr;
  extract_queried_url(request, queried_url);
  struct authserverrecord auth_server_table[50];
  struct sockaddr_storage recd_ns_ips[20];
  uint16_t zero_buffer[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  int recd_ns_count = 0;
  int recd_ip_count = 0; // additional records
  int response_size = 0;
  // if an entry in recd_ns_ips is 0.0.0.0, we treat it as unassigned
  memset(recd_ns_ips,0,sizeof(recd_ns_ips));
  memset(recd_ns_name,0,20*255);
  int retries = 5;
  
  if(debug)
    printf("resolve name called with packet size %d\n",packet_size);
  //note change this to try in all servers
  int chosen = random()%nameserver_count;
  struct sockaddr_storage * chosen_ns = &nameservers[chosen];
  if(debug)
  {
    printf("\nAsking for record using server %d out of %d\n",chosen, nameserver_count);
  }

  // using sockaddr to actually send a packet, so make sure the 
  //  port is set
  //
  if(debug)
    printf("ss family: %d\n",chosen_ns->ss_family);
  if(chosen_ns->ss_family == AF_INET)
    ((struct sockaddr_in *)chosen_ns)->sin_port = htons(53);
  else if(chosen_ns->ss_family==AF_INET6)
    ((struct sockaddr_in6 *)chosen_ns)->sin6_port = htons(53);
  else
  {
    // this can happen during recursion if a NS w/o a glue record
    // doesn't resolve properly
    if (debug)
      printf("ss_family not set\n");
  }
  int send_count = sendto(sock, request, packet_size, 0, 
      (struct sockaddr *)chosen_ns, sizeof(struct sockaddr_in6));
  if(send_count<0){
    perror("Send failed");
    exit(1);
  }

  // await the response - not calling recvfrom, don't care who is responding
  response_size = recv(sock, response, UDP_RECV_SIZE, 0);
  // discard anything that comes in as a query instead of a response
  if ((response_size > 0) && ((ntohs(((struct dns_hdr *)response)->flags) & 0x8000) == 0))
  {
    if(debug){
      printf("flags: 0x%x\n",ntohs(((struct dns_hdr *)response)->flags) & 0x8000);
      printf("received a query while expecting a response\n");
    }
  }
  if(debug) printf("response size: %d\n",response_size);

  // parse the response to get our answer
  struct dns_hdr * header = (struct dns_hdr *) response;
  uint8_t * answer_ptr = response + sizeof(struct dns_hdr);

  // now answer_ptr points at the first question.
  int question_count = ntohs(header->q_count);
  int answer_count = ntohs(header->a_count);
  int auth_count = ntohs(header->auth_count);
  int other_count = ntohs(header->other_count);

  // skip questions
  for(int q=0; q<question_count; q++){
    char string_name[255];
    memset(string_name,0,255);
    int size=from_dns_style(response, answer_ptr,string_name);
    answer_ptr+=size;
    answer_ptr+=4;
  }

  if(debug)
    printf("Got %d+%d+%d=%d resource records total.\n",answer_count,auth_count,other_count,answer_count+auth_count+other_count);
  if(answer_count+auth_count+other_count>50){
    printf("ERROR: got a corrupt packet\n");
    return -1;
  }

  
  for(int a=0; a<answer_count+auth_count+other_count;a++)
  {
    // first the name this answer is referring to
    
    char string_name[255], auth_server_name[255];
    int auth_server_name_len = 0;
    int dnsnamelen=from_dns_style(response,answer_ptr,string_name);
    uint16_t query_id;
    answer_ptr += dnsnamelen;

    // then fixed part of the RR record
    struct dns_rr* rr = (struct dns_rr*)answer_ptr;
    answer_ptr+=sizeof(struct dns_rr);

    //A record
    if(htons(rr->type)==RECTYPE_A)
    {
    
    if(strcmp(string_name, queried_url) == 0)
    {
    if(debug)
        printf("The final A record is found\n");
    return response_size;
    }
    for(int i = 0; i < recd_ns_count; i++)
    {
        if(strcmp(auth_server_table[i].server_name, string_name) == 0)
        {
            if(memcmp((void *)&zero_buffer, (void *)&(((struct sockaddr_in *)(&auth_server_table[i].server_addr))->sin_addr), 4) == 0)
            {
            auth_server_table[i].server_addr.ss_family = AF_INET;
            server_addr = (struct sockaddr_in *)&auth_server_table[i].server_addr;
            memcpy((void *)&(server_addr->sin_addr), (void *)answer_ptr, 4);
            server_addr->sin_port = htons(53);
            }
            else
            {
            strcpy(auth_server_table[recd_ns_count].server_name, string_name);
            server_addr = (struct sockaddr_in *)&auth_server_table[recd_ns_count].server_addr;
            memcpy((void *)&(server_addr->sin_addr), (void *)answer_ptr, 4);
            server_addr6->sin6_port = htons(53);
            recd_ns_count ++;
            break;
            }
        }
    }
    //note: need to add logic for out of order records
      if(debug)
        {
        
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntoa(*((struct in_addr *)answer_ptr)));
        }
    }
    //NS record
    else if(htons(rr->type)==RECTYPE_NS) 
    {
    auth_server_name_len = from_dns_style(response,answer_ptr,auth_server_name);
      if(debug)
        printf("The name %s can be resolved by NS: %s\n",
            string_name, auth_server_name);
      strcpy(auth_server_table[recd_ns_count].domain, string_name);
      strcpy(auth_server_table[recd_ns_count].server_name, auth_server_name);
      recd_ns_count++;
    }
    //CNAME record
    else if(htons(rr->type)==RECTYPE_CNAME)
    {
      char ns_string[255];
      int ns_len=from_dns_style(response,answer_ptr,ns_string);
      if(debug)
        printf("The name %s is also known as %s.\n",				
            string_name, ns_string);
      uint8_t query_buff[256];
      query_id = (uint16_t) (random() & 0xffff);
      int query_len = construct_query(query_buff, 256, ns_string, 255, query_id);
      int response_len = resolve_name(sock, query_buff, query_len, response, root_servers, root_server_count);
      struct sockaddr_storage extracted_address;
      if (extract_answer(response, &extracted_address) == 1)
      {
      response_len = construct_response(response, 250, string_name, &extracted_address, ntohs(request_header->id), 12);
      return response_len;
      }
      else if(debug)
      {
      printf("A record not found\n");
      }
    }
    // SOA record
    else if(htons(rr->type)==RECTYPE_SOA)
    {
      if(debug)	
        printf("Ignoring SOA record\n");
    }
    // AAAA record
    
    else if(htons(rr->type)==RECTYPE_AAAA)	
    {
    for(int i = 0; i < recd_ns_count; i++)
    {
        if(strcmp(auth_server_table[i].server_name, string_name) == 0 )
        {
            if(memcmp((void *)&zero_buffer, (void *)&(((struct sockaddr_in6 *)(&auth_server_table[i].server_addr))->sin6_addr), 16) == 0)
            {
            auth_server_table[i].server_addr.ss_family = AF_INET6;
            server_addr6 = (struct sockaddr_in6 *)&auth_server_table[i].server_addr;
            memcpy((void *)&(server_addr6->sin6_addr), (void *)answer_ptr, 16);
            server_addr6->sin6_port = htons(53);
            }
            else
            {
            strcpy(auth_server_table[recd_ns_count].server_name, string_name);
            server_addr6 = (struct sockaddr_in6 *)&auth_server_table[recd_ns_count].server_addr;
            memcpy((void *)&(server_addr6->sin6_addr), (void *)answer_ptr, 16);
            server_addr6->sin6_port = htons(53);
            recd_ns_count ++;
            break;
            }
        }
    }
      if(debug)
      {
        char printbuf[INET6_ADDRSTRLEN];	
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntop(AF_INET6, answer_ptr, printbuf,INET6_ADDRSTRLEN));
      }
      
    }
    else
    {
      if(debug)
        printf("got unknown record type %hu\n", htons(rr->type));
    }
    answer_ptr+=htons(rr->datalen);
  }
  char ip_addr[INET_ADDRSTRLEN];
  struct in_addr * addr;
  struct sockaddr_storage new_list_of_name_servers[20];
  int valid_ns_count = 0;
  for(int i=0;i<recd_ns_count && i<20;i++)
  {
  if(memcmp((void *)&zero_buffer, (void *)&(((struct sockaddr_in *)(&auth_server_table[i].server_addr))->sin_addr), 4) != 0)
  {
  new_list_of_name_servers[valid_ns_count] = auth_server_table[i].server_addr;
  valid_ns_count ++;
  server_addr= (struct sockaddr_in *)&(auth_server_table[i].server_addr);
  addr = (&server_addr->sin_addr);
  inet_ntop(AF_INET, (void *)addr, ip_addr, INET_ADDRSTRLEN);
  if(debug)
  printf("%s||%s||%s\n", auth_server_table[i].domain, auth_server_table[i].server_name, ip_addr);
  }
  }
  response_size = resolve_name(sock, request, packet_size, response, new_list_of_name_servers, valid_ns_count);
  
  return response_size;

}
*/
int main(int argc, char ** argv){
  int port_num=53;
  int sockfd;
  int sent_count = 0;
  struct sockaddr_in6 server_address;
  struct dns_hdr * header=NULL;
  char * question_domain=NULL;
  char client_ip[INET6_ADDRSTRLEN];
  char *optString = "dp";
  struct timeval timeout;
  struct sockaddr_storage temp;
  int opt = getopt(argc, argv, optString);

  while( opt != -1){
    switch(opt) {
      case 'd':
        debug = 1;
        printf("Debug mode\n");
        break;
      case 'p':
        port_num=atoi(argv[optind]);
        break;
      case '?':
        usage();
        break;
    }
    opt = getopt(argc, argv, optString);
  }

  read_server_file();

  //Create socket as DNS Server
  printf("Creating socket on port: %d\n", port_num);
  sockfd=socket(AF_INET6, SOCK_DGRAM, 0);
  if(sockfd<0){
    perror("Unable to screate socket");
    return -1;
  }
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));


  memset(&server_address, 0, sizeof(server_address));
  server_address.sin6_family=AF_INET6;
  server_address.sin6_addr = in6addr_any;
  server_address.sin6_port=htons(port_num);
  if(bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address))<0){
    perror("Uable to bind");
    return -1;
  }
  if (debug)
    printf("Bind successful\n");
  
  socklen_t addrlen = sizeof(struct sockaddr_in6);
  struct sockaddr_in6 client_address;
  uint8_t request[UDP_RECV_SIZE];
  uint8_t response[UDP_RECV_SIZE];
  int packet_size;
  if(debug)
    printf("Waiting for query...\n");

  while(1){
        printf("%d<>\n", addrlen);
    if((packet_size = recvfrom(sockfd, request, UDP_RECV_SIZE, 0, (struct sockaddr *)&client_address, &addrlen))<0){
      for(struct dns_query * query=queries; query!=NULL; query=query->next)
      {
      packet_size = timeout_query(query, response, UDP_RECV_SIZE, &temp);
      if(temp.ss_family == AF_INET)
        {
        if(debug)
        printf("sending request to ipv4:%s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&temp)->sin_addr), client_ip, INET_ADDRSTRLEN));
        sent_count = sendto(sockfd, response, packet_size, 0, (struct sockaddr*)&temp, sizeof(struct sockaddr));
        }
      else if(temp.ss_family == AF_INET6)
        {
        if(debug)
        printf("sending request to ipv6:%s\n", inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&temp)->sin6_addr), client_ip, INET6_ADDRSTRLEN));
        sent_count = sendto(sockfd, response, packet_size, 0, (struct sockaddr*)&temp, sizeof(struct sockaddr_in6));
        }
      }
      perror("recvfrom error");
      printf("timed out... %d\n",packet_size);
      continue;
    }
    else
    {
    if(debug)
      printf("received request of size %d\n",packet_size);
    if(packet_size<(int)(sizeof(struct dns_hdr)+sizeof(struct dns_query_section))){
      perror("Receive invalid DNS request");
      continue;
    }
    packet_size = process_request(request, packet_size, (struct sockaddr_storage *)&client_address, response, UDP_RECV_SIZE, &temp);
    if(packet_size >= 0)
    {
    if(temp.ss_family == AF_INET)
        {
        if(debug)
        printf("sending request to ipv4:%s\n", inet_ntop(AF_INET, &(((struct sockaddr_in *)&temp)->sin_addr), client_ip, INET_ADDRSTRLEN));
        sent_count = sendto(sockfd, response, packet_size, 0, (struct sockaddr*)&temp, sizeof(struct sockaddr_in));
        }
    else if(temp.ss_family == AF_INET6)
        {
        if(debug)
        printf("sending request to ipv6:%s\n", inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&temp)->sin6_addr), client_ip, INET6_ADDRSTRLEN));
        sent_count = sendto(sockfd, response, packet_size, 0, (struct sockaddr*)&temp, sizeof(struct sockaddr_in6));
        }
    }
    }

   if(debug)
      printf("sent :%d\nWaiting for query...\n", sent_count);

  }

  return 0;
}


