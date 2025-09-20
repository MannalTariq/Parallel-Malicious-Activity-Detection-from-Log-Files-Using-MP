#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define MAX_LINE_LENGTH 1024
#define MAX_ENTRIES 1000 // Maximum log entries to track
#define MAX_IP_LENGTH 16

// Structure to track multiple logs from the same source IP
typedef struct {
    char src_ip[MAX_IP_LENGTH];
    int high_port_attempts;
    int dos_attempts;
    int recon_attempts;
    int dst_ports[MAX_ENTRIES]; // Track destination ports for reconnaissance
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
    int packet_stats[10]; // Assume max 10 packets

    // Tokenize the line by commas
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
void process_logs(const char *filename, int rank, int size, int *backdoorCounter, int *dosCounter, int *reconCounter) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    char line[MAX_LINE_LENGTH];
    IPLog ip_logs[MAX_ENTRIES];
    int log_count = 0;

    // Initialize IP logs
    initialize_ip_logs(ip_logs);

    // Count total lines in the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Calculate the number of lines for each process
    int total_lines = 0;
    while (fgets(line, sizeof(line), file)) {
        total_lines++;
    }

    int lines_per_process = total_lines / size;
    int remaining_lines = total_lines % size;

    // Determine the starting line for each process
    int start_line = rank * lines_per_process + (rank < remaining_lines ? rank : remaining_lines);
    int lines_to_read = lines_per_process + (rank < remaining_lines ? 1 : 0);

    // Reset the file pointer to the beginning
    fseek(file, 0, SEEK_SET);

    // Skip lines for the current process
    for (int i = 0; i < start_line; i++) {
        fgets(line, sizeof(line), file);
    }

    // Each process reads its allotted lines
    for (int i = 0; i < lines_to_read; i++) {
        if (fgets(line, sizeof(line), file)) {
            process_log_line(line, ip_logs, &log_count, backdoorCounter, dosCounter, reconCounter);
        }
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    // Local counts for each process
    double start_time=0,end_time=0,local_time=0,max_time=0;
    int backdoorCounter = 0, dosCounter = 0, reconCounter = 0;

    start_time=MPI_Wtime();
    // Process the logs file for each process
    process_logs("network_logs.csv", rank, size, &backdoorCounter, &dosCounter, &reconCounter); // Change to your actual file name

    // Variables to store the global sums
    int global_backdoorCounter = 0, global_dosCounter = 0, global_reconCounter = 0;

    // Use MPI_Reduce to sum up the counts from all processes
    MPI_Reduce(&backdoorCounter, &global_backdoorCounter, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&dosCounter, &global_dosCounter, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&reconCounter, &global_reconCounter, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    end_time=MPI_Wtime();
    local_time=end_time-start_time;


    MPI_Reduce(&local_time, &max_time, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);

    // The master process (rank 0) prints the total counts
    if (rank == 0) {
        printf("Total Backdoor Count: %d\n", global_backdoorCounter);
        printf("Total DoS Count: %d\n", global_dosCounter);
        printf("Total Reconnaissance Count: %d\n", global_reconCounter);
        printf("Time taken (parallel version): %f seconds\n", max_time);

        // If needed, display individual results from each process
        printf("-----------------------------\n");
        for (int i = 0; i < size; i++) {
            if (i == 0) {
                printf("Process %d:\n", i);
                printf("Backdoor Count: %d\n", backdoorCounter); // Local rank 0 values already known
                printf("DoS Count: %d\n", dosCounter);
                printf("Reconnaissance Count: %d\n", reconCounter);
            } else {
                // Receive local counts from other processes
                int local_backdoor, local_dos, local_recon;
                MPI_Recv(&local_backdoor, 1, MPI_INT, i, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                MPI_Recv(&local_dos, 1, MPI_INT, i, 1, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                MPI_Recv(&local_recon, 1, MPI_INT, i, 2, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

                printf("Process %d:\n", i);
                printf("Backdoor Count: %d\n", local_backdoor);
                printf("DoS Count: %d\n", local_dos);
                printf("Reconnaissance Count: %d\n", local_recon);
            }
            printf("-----------------------------\n");
        }
    } else {
        // Non-master processes send their local counts to the master
        MPI_Send(&backdoorCounter, 1, MPI_INT, 0, 0, MPI_COMM_WORLD);
        MPI_Send(&dosCounter, 1, MPI_INT, 0, 1, MPI_COMM_WORLD);
        MPI_Send(&reconCounter, 1, MPI_INT, 0, 2, MPI_COMM_WORLD);
    }

    MPI_Finalize();
    return 0;
}