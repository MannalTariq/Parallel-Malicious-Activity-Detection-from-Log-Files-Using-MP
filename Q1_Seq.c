#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE_LENGTH 1024
#define MAX_ENTRIES 1000 
#define MAX_IP_LENGTH 16

// Structure to track multiple logs from the same source IP
typedef struct {
    char src_ip[MAX_IP_LENGTH];
    int high_port_attempts;
    int dos_attempts;
    int recon_attempts;
    int dst_ports[MAX_ENTRIES];
    int port_count;
} IPLog;

// Helper function to check if a port exists in the port list
int port_exists(int port, int *port_list, int count) {
    for (int i = 0; i < count; i++) {
        if (port_list[i] == port) {
            return 1;
        }
    }
    return 0;
}

// Function to initialize IP logs
void initialize_ip_logs(IPLog *ip_logs) {
    for (int i = 0; i < MAX_ENTRIES; i++) {
        ip_logs[i].high_port_attempts = 0;
        ip_logs[i].dos_attempts = 0;
        ip_logs[i].recon_attempts = 0;
        ip_logs[i].port_count = 0;
        memset(ip_logs[i].src_ip, 0, sizeof(ip_logs[i].src_ip)); // Clear IP
    }
}

// Function to process each log line
void process_log_line(char *line, IPLog *ip_logs, int *log_count, int *backdoorCounter, int *dosCounter, int *reconCounter) {
    char src_ip[MAX_IP_LENGTH], dst_ip[MAX_IP_LENGTH], protocol[10], flag[10], service[10];
    int src_port, dst_port, src_bytes, dst_bytes, packet_count = 0;
    int packet_stats[10]; // Assuming max 10 packets

    // Tokenizing the line by commas
    char *token = strtok(line, ",");
    int column = 0;

    // Process each field from the CSV line
    while (token) {
        switch (column) {
            case 0: strncpy(src_ip, token, sizeof(src_ip)); break;
            case 1: src_port = atoi(token); break;
            case 2: strncpy(dst_ip, token, sizeof(dst_ip)); break;
            case 3: dst_port = atoi(token); break;
            case 4: strncpy(protocol, token, sizeof(protocol)); break;
            case 5: strncpy(flag, token, sizeof(flag)); break;
            case 6: atof(token); break; // Duration
            case 7: src_bytes = atoi(token); break;
            case 8: dst_bytes = atoi(token); break;
            case 9: // Packet stats
            case 10:
            case 11:
            case 12:
                if (packet_count < 10) {
                    packet_stats[packet_count++] = atoi(token);
                }
                break;
            case 13: strncpy(service, token, sizeof(service)); break;
            // Not using Other col with my current logic
        }
        token = strtok(NULL, ",");
        column++;
    }

    // Find or create a log entry for this source IP
    int ip_index = -1;
    for (int i = 0; i < *log_count; i++) {
        if (strcmp(ip_logs[i].src_ip, src_ip) == 0) {
            ip_index = i;
            break;
        }
    }
    if (ip_index == -1) { // New IP, create entry
        ip_index = (*log_count)++;
        strncpy(ip_logs[ip_index].src_ip, src_ip, sizeof(ip_logs[ip_index].src_ip));
    }

    // Backdoor Detection
    if ((dst_port > 1024 && dst_port < 65535) &&
        strcmp(service, "smtp") != 0 &&
        strcmp(service, "http") != 0 &&
        strcmp(service, "dns") != 0 &&
        strcmp(service, "ftp") != 0) {
        ip_logs[ip_index].high_port_attempts++;
        if (ip_logs[ip_index].high_port_attempts > 50) {
            (*backdoorCounter)++;
        }
    }

    // DoS Detection
    if (packet_count > 1000 || src_bytes > 100000 || dst_bytes > 100000) {
        ip_logs[ip_index].dos_attempts++;
        if (ip_logs[ip_index].dos_attempts > 3) {
            (*dosCounter)++;
        }
    }

    // Reconnaissance Detection
    if (!port_exists(dst_port, ip_logs[ip_index].dst_ports, ip_logs[ip_index].port_count)) {
        ip_logs[ip_index].dst_ports[ip_logs[ip_index].port_count++] = dst_port;
        ip_logs[ip_index].recon_attempts++;
        if (ip_logs[ip_index].recon_attempts > 5) {
            (*reconCounter)++;
        }
    }
}

// Main processing function
void process_logs(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    char line[MAX_LINE_LENGTH];
    IPLog ip_logs[MAX_ENTRIES];
    int log_count = 0;
    int backdoorCounter = 0;
    int dosCounter = 0;
    int reconCounter = 0;

    // Initialize IP logs
    initialize_ip_logs(ip_logs);

    // Read each line from the CSV file
    while (fgets(line, sizeof(line), file)) {
        process_log_line(line, ip_logs, &log_count, &backdoorCounter, &dosCounter, &reconCounter);
    }

    // Output results
    printf("Backdoor Count: %d\n", backdoorCounter);
    printf("DoS Count: %d\n", dosCounter);
    printf("Reconnaissance Count: %d\n", reconCounter);

    fclose(file);
}

int main() {
    clock_t start_time=0,end_time=0;
    double time=0;

    //calculating time from the process start to end
    start=clock();
    process_logs("network_logs.csv");
    end=clock();

    time=((double) (end_time-start_time)) / CLOCKS_PER_SEC;
    printf("Time taken: %f seconds\n", time);
    return 0;
}
