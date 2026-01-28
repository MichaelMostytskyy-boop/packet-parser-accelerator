/* Michael Mostytskyy
   Project: Packet Parser
   Description:
   Hardware implementation of a basic IPv4/TCP/UDP packet parser.
   Extracts IP addresses, ports, and verifies IP header checksum.
*/

module packet_parser (
    // System Signals
    input  logic        clk,
    input  logic        rst_n,

    // Data Interface
    input  logic [7:0]  data_in,      // Input data byte
    input  logic        valid_in,     // Data validity flag
    input  logic        last_in,      // End of packet indicator

    // Parsed Outputs
    output logic [31:0] src_ip,       // Extracted Source IP
    output logic [31:0] dst_ip,       // Extracted Destination IP
    output logic [15:0] src_port,     // Extracted Source Port
    output logic [15:0] dst_port,     // Extracted Destination Port
    output logic        is_tcp,       // TCP Protocol detected
    output logic        is_udp,       // UDP Protocol detected

    // Status Outputs
    output logic        checksum_ok,  // High if IP Header Checksum is valid
    output logic        parser_done,  // High when packet processing finishes
    output logic        parser_error  // High if protocol/length error occurs
);

    // Protocol Constants
    localparam [15:0] ETH_TYPE_IPV4 = 16'h0800;
    localparam [7:0]  PROTO_TCP     = 8'h06;
    localparam [7:0]  PROTO_UDP     = 8'h11;

    // FSM States
    typedef enum logic [2:0] {
        IDLE,
        PARSE_ETH, // Ethernet Header processing
        PARSE_IP,  // IP Header processing
        PARSE_L4,  // TCP/UDP Ports processing
        WAIT_END,  // Wait for packet end (if irrelevant)
        DONE
    } state_t;

    state_t current_state, next_state;

    // Internal Counters & Buffers
    logic [15:0] byte_cnt;        // General purpose byte counter
    logic [7:0]  prev_byte;       // Previous byte storage for 16-bit matching

    logic [15:0] ip_len_bytes;    // Total Length extracted from IP Header
    logic [7:0]  captured_proto;  // Protocol field extracted from IP Header

    logic [7:0]  ip_hdr [0:59];   // Buffer to store IP header for checksum
    logic [15:0] ip_byte_cnt;     // Pointer within the IP header

    // Checksum Calculation Signals
    logic [31:0] fold_stage_1, fold_stage_2, fold_stage_3;
    logic [31:0] ip_sum_raw, ip_sum_folded;
    logic [15:0] hdr_checksum;    // Checksum field from the packet itself
    logic [15:0] calc_checksum;   // Calculated checksum result
    logic [31:0] sum0, sum1;

    // Error & Output Control
    logic err_this_cycle;         // Instantaneous error flag
    logic checksum_ok_r;          // Registered result for stability

    assign checksum_ok = checksum_ok_r;
    assign parser_done = (current_state == DONE);

    // FSM Next State Logic
    always @(*) begin
        next_state = current_state;

        case (current_state)
            IDLE:       if (valid_in) next_state = PARSE_ETH;

            PARSE_ETH: begin
                if (valid_in) begin
                    if (last_in) next_state = DONE;
                    else if (byte_cnt == 13) begin
                        // Check for IPv4 EtherType (0x0800)
                        if ({prev_byte, data_in} == ETH_TYPE_IPV4) next_state = PARSE_IP;
                        else next_state = WAIT_END;
                    end
                end
            end

            PARSE_IP: begin
                if (valid_in) begin
                    if (last_in) next_state = DONE;
                    // Check Version (4) and IHL (>=5)
                    else if (ip_byte_cnt == 0) begin
                        if (data_in[7:4] != 4 || data_in[3:0] < 5) next_state = WAIT_END;
                    end
                    // Check Protocol at end of header
                    else if (ip_byte_cnt == (ip_len_bytes - 1)) begin
                        if (captured_proto == PROTO_TCP || captured_proto == PROTO_UDP) next_state = PARSE_L4;
                        else next_state = WAIT_END;
                    end
                end
            end

            PARSE_L4: begin
                if (valid_in) begin
                    if (last_in) next_state = DONE;
                    else if (byte_cnt == 3) next_state = WAIT_END; // Only need 4 bytes (Src/Dst Port)
                end
            end

            WAIT_END:   if (valid_in && last_in) next_state = DONE;

            DONE: begin
                if (valid_in) next_state = PARSE_ETH; // Back-to-back support
                else next_state = IDLE;
            end

            default: next_state = IDLE;
        endcase
    end

    // Error Detection Logic (Combinational)
    always @(*) begin
        err_this_cycle = 1'b0;

        if (valid_in) begin
            case (current_state)
                PARSE_ETH: begin
                    if (last_in && (byte_cnt < 13)) err_this_cycle = 1'b1; // Undersized Eth header
                end

                PARSE_IP: begin
                    if (ip_byte_cnt == 0) begin
                        if (data_in[7:4] != 4 || data_in[3:0] < 5) err_this_cycle = 1'b1; // Bad IP Version/IHL
                    end
                    if (last_in && (ip_byte_cnt < (ip_len_bytes - 1))) err_this_cycle = 1'b1; // Truncated IP
                end

                PARSE_L4: begin
                    if (last_in && (byte_cnt < 3)) err_this_cycle = 1'b1; // Truncated Ports
                end

                default: err_this_cycle = 1'b0;
            endcase
        end
    end

    // Sequential Logic (State Update & Data Path)
    integer k;
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            current_state  <= IDLE;
            byte_cnt       <= 0;
            prev_byte      <= 0;

            ip_len_bytes   <= 20;
            captured_proto <= 0;

            ip_byte_cnt    <= 0;

            src_ip         <= 0;
            dst_ip         <= 0;
            src_port       <= 0;
            dst_port       <= 0;

            is_tcp         <= 0;
            is_udp         <= 0;
            parser_error   <= 0;

            checksum_ok_r  <= 1'b0;

            for (k=0; k<60; k++) ip_hdr[k] <= 8'h00;
        end else begin
            current_state <= next_state;

            // Checksum Flag Control
            if (current_state == IDLE && valid_in) begin
                checksum_ok_r <= 1'b0;
            end

            if ((current_state != DONE) && (next_state == DONE)) begin
                checksum_ok_r <= (!(parser_error || err_this_cycle)) && (calc_checksum == hdr_checksum);
            end

            // Byte Counter Management
            if (current_state != next_state && next_state != DONE) begin
                byte_cnt <= 0;
            end else if (valid_in && current_state != DONE) begin
                if (current_state != PARSE_IP)
                    byte_cnt <= byte_cnt + 1;
            end

            // IP Header Extraction
            if (current_state != PARSE_IP && next_state == PARSE_IP) begin
                ip_byte_cnt <= 0;
                for (k=0; k<60; k++) ip_hdr[k] <= 8'h00; // Clear buffer
            end else if (current_state == PARSE_IP && valid_in) begin
                if (ip_byte_cnt < 60)
                    ip_hdr[ip_byte_cnt] <= data_in; // Capture byte for checksum
                ip_byte_cnt <= ip_byte_cnt + 1;
            end

            // Error Flag Update
            if ((current_state == IDLE && valid_in) || (current_state == DONE && valid_in)) begin
                parser_error <= 1'b0;
            end else begin
                parser_error <= parser_error | err_this_cycle;
            end

            // Data Field Extraction
            case (current_state)
                IDLE: begin
                    if (valid_in) begin
                        is_tcp       <= 0;
                        is_udp       <= 0;
                        prev_byte    <= data_in;
                        byte_cnt     <= 1;
                    end
                end

                PARSE_ETH: begin
                    if (valid_in) begin
                        prev_byte <= data_in; // Store for 16-bit EtherType check
                    end
                end

                PARSE_IP: begin
                    if (valid_in) begin
                        if (ip_byte_cnt == 0) begin
                            ip_len_bytes <= {data_in[3:0], 2'b00}; // Extract Length (IHL * 4)
                        end

                        if (ip_byte_cnt == 9)  captured_proto <= data_in; // Protocol ID

                        // Extract Source IP
                        if (ip_byte_cnt == 12) src_ip[31:24] <= data_in;
                        if (ip_byte_cnt == 13) src_ip[23:16] <= data_in;
                        if (ip_byte_cnt == 14) src_ip[15:8]  <= data_in;
                        if (ip_byte_cnt == 15) src_ip[7:0]   <= data_in;

                        // Extract Dest IP
                        if (ip_byte_cnt == 16) dst_ip[31:24] <= data_in;
                        if (ip_byte_cnt == 17) dst_ip[23:16] <= data_in;
                        if (ip_byte_cnt == 18) dst_ip[15:8]  <= data_in;
                        if (ip_byte_cnt == 19) dst_ip[7:0]   <= data_in;

                        if (ip_byte_cnt == (ip_len_bytes - 1)) begin
                            if (captured_proto == PROTO_TCP) is_tcp <= 1;
                            else if (captured_proto == PROTO_UDP) is_udp <= 1;
                        end
                    end
                end

                PARSE_L4: begin
                    if (valid_in) begin
                        // Extract Ports
                        if (byte_cnt == 0) src_port[15:8] <= data_in;
                        if (byte_cnt == 1) src_port[7:0]  <= data_in;
                        if (byte_cnt == 2) dst_port[15:8] <= data_in;
                        if (byte_cnt == 3) dst_port[7:0]  <= data_in;
                    end
                end

                DONE: begin
                    if (valid_in) begin
                        byte_cnt     <= 1;
                        prev_byte    <= data_in;
                        is_tcp       <= 0;
                        is_udp       <= 0;
                    end
                end
            endcase
        end
    end

    // Checksum Logic: Folding (Sum 16-bit words)
    integer i;
    always @(*) begin
        ip_sum_raw = 0;
        for (i = 0; i < 60; i = i + 2) begin
            if (i < ip_len_bytes)
                ip_sum_raw = ip_sum_raw + {ip_hdr[i], ip_hdr[i+1]};
        end
        // Fold 32-bit sum to 16-bit
        fold_stage_1  = ip_sum_raw[31:16] + ip_sum_raw[15:0];
        fold_stage_2  = fold_stage_1[31:16] + fold_stage_1[15:0];
        fold_stage_3  = fold_stage_2[31:16] + fold_stage_2[15:0];
        ip_sum_folded = fold_stage_3;
    end

    // Checksum Logic: Calculation (Verify against header checksum)
    integer j;
    always @(*) begin
        hdr_checksum = {ip_hdr[10], ip_hdr[11]};
        sum0 = 0;

        for (j = 0; j < 60; j = j + 2) begin
            if (j < ip_len_bytes) begin
                if (j == 10) sum0 = sum0 + 16'h0000; // Skip checksum field itself
                else         sum0 = sum0 + {ip_hdr[j], ip_hdr[j+1]};
            end
        end

        sum1 = sum0;
        while (sum1[31:16] != 0)
            sum1 = sum1[15:0] + sum1[31:16];

        calc_checksum = ~sum1[15:0];
    end

endmodule