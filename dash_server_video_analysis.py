import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
import numpy as np
import re
import pandas as pd
import os
import bisect
from scipy.stats import rankdata
from datetime import datetime, timedelta
import io
import math

FreeBSD_RESULT = False
Linux_RESULT = True
SEARCH_RESULT = True
CRASH_TEST_RESULT = False

cwd = os.getcwd()
base_path = "/home/maryam/SEARCH/dash_test/dash_results/1_linux_desktop_cablemodem_home/"
pcap_csv_path = "" # pcap_csv_path = os.path.join(base_path, "data/pcap_server")
fig_path = os.path.join(base_path, "figures")
if not os.path.exists(fig_path):
    os.makedirs(fig_path, exist_ok=True)

server_data_path = os.path.join(base_path, "server")
client_data_path = os.path.join(base_path, "client")

FOLDER_PATH = "data/log_search"

SERVER_IP = "130.215.28.249"
INTERVAL = 0.5  # 1s

###################################### Functions ##################################
def calculate_delivery_rate_per_ack(bytes_acked, now, rtt):
    delivery_rates = []
    time_cal_delv_rates = []
    for i in range(len(now)):
        target_time = now[i] - rtt[i]
        if target_time <= 0:
            start_index = i+1
            continue
        # Find rightmost index j where now[j] <= target_time
        j = bisect.bisect_right(now, target_time, 0, i) - 1
        if j >= 0:
            delta_bytes = bytes_acked[i] - bytes_acked[j]
            rate = delta_bytes / rtt[i]
            delivery_rates.append(rate)
            time_cal_delv_rates.append(now[i])
            
    return delivery_rates, start_index, time_cal_delv_rates if delivery_rates else None

################## Parse start and end times from client filenames ####################
def extract_client_times(folder):
    files = sorted([f for f in os.listdir(folder) if f.startswith("Tester") and f.endswith(".txt")])
    runs = []
    for i in range(0, len(files), 2):
        start_file = files[i]
        end_file = files[i + 1]
        time_fmt = "%Y-%m-%d_%H-%M-%S"
        start_str = "_".join(start_file.split("_")[1:]).replace(".txt", "")
        end_str = "_".join(end_file.split("_")[1:]).replace(".txt", "")
        start_time = datetime.strptime(start_str, time_fmt) - timedelta(seconds=10)
        end_time = datetime.strptime(end_str, time_fmt)
        runs.append((start_time, end_time))
    return runs

##################  Parse log file for flows #########################
def parse_ccrg_log(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()

    flows = {}
    for line in lines:
        if "SEARCH_EXIT_RATE" in line:
            match = re.search(r'^.*?(\d{2}:\d{2}:\d{2}).*?\[flow_pointer: (0x[0-9a-f]+)\].*?\[now (\d+)\].*?\[delta_bytes (\d+)\].*?\[rtt_us (\d+)\].*?\[rate (\d+) MB/s\].*?\[delta_bytes_one_bin (\d+)\].*?\[mb_per_sec_one_bin (\d+)\]', line)
            if match:
                time_str = match.group(1)
                fp = match.group(2)
                data = {
                    "log_time": time_str,
                    "now": int(match.group(3)),
                    "delta_bytes": int(match.group(4)),
                    "rtt_us": int(match.group(5)),
                    "rate_Mbps": int(match.group(6)),
                    "delta_bytes_one_bin": int(match.group(7)),
                    "mb_per_sec_one_bin": int(match.group(8)),
                }
                flows.setdefault(fp, []).append(data)
    return flows

##################### Resolution label mapping #########################
def resolution_to_label(res_str):
    width, height = map(int, res_str.split('x'))
    if height < 480:
        return '360p'
    elif height < 720:
        return '480p'
    elif height < 1080:
        return '720p'
    elif height < 1440:
        return '1080p'
    elif height < 2160:
        return '2K'
    else:
        return '4K'
##################### Parse client log file for bitrates #########################
def parse_client_log_file(filepath):
    times, bitrates, resolutions = [], [], []
    client_info = {}

    with open(filepath, "r") as f:
        lines = f.readlines()
        for entry in lines:
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(':')
            if len(parts) != 2:
                continue
            time_str, rest = parts[0], parts[1]
            try:
                time = float(time_str)
                fps, resolution, bitrate, buffer = rest.split(',')
                times.append(time)
                resolutions.append(resolution_to_label(resolution))
                bitrates.append(float(bitrate))  # Bitrate is in Kbps
            except Exception as e:
                print(f"Skipping malformed entry: {entry}")

    client_info['times'] = np.array(times)
    client_info['bitrates'] = np.array(bitrates)
    client_info['resolutions'] = np.array(resolutions)
    return client_info

####################### Plotting helper functions #########################
import matplotlib.pyplot as plt

def plot_vlines(times, color, label, linewidth):
    if times is None or len(times) == 0:
        return
    if hasattr(times, 'tolist'):
        times = times.tolist()
    times = [t for t in times if t is not None]
    if not times:
        return

    for i, t in enumerate(times):
        plt.axvline(x=t, color=color, linestyle='--', linewidth=linewidth, label=label if i == 0 else None)


###################################### FREEBSD ####################################
if FreeBSD_RESULT:
    if SEARCH_RESULT:

        folder_path = os.path.join(base_path, FOLDER_PATH)

        if os.path.isdir(folder_path):
            print("Processing:", folder_path)
            # count the number of files in the directory
            num_files = len([name for name in os.listdir(folder_path) if name.endswith(".csv")])

            # extract flow pointer part from filename (log_data{num}_{flow_pointer}.csv)
            flow_pointers = []
            for name in os.listdir(folder_path):
                if name.startswith("log_data") and name.endswith(".csv"):
                    match = re.search(r'_(0x[0-9a-fA-F]+)\.csv', name)
                    if match:
                        flow_pointer = match.group(1)
                        flow_pointers.append(flow_pointer)

            for num in range(num_files):
                for flow_pointer in flow_pointers:

                    time_s_log_list = []
                    cwnd_MB_log_list = []
                    ssthresh_MB_log_list = []
                    mss_log = None
                    search_exit_s_log_list = []
                    loss_time_s_log_list = []
                    rto_time_s_log_list = []
                    ecn_time_s_log_list = []
                    after_idle_time_s_log_list = []
                    srtt_s_log_list = []
                    currack_log_list = []
                    total_bytes_acked_MB_log_list = []
                    norm_values_list = []
                    search_time_s_log_list = []
                    send_next_list = []
                    initial_seq_sent_list = []
                    each_delv_bytes_MB_log_list = []
                    sent_bytes = None
                    sent_MB_list = []
                    curr_delv_window_MB_list = []
                    prev_delv_window_MB_list = []

                    # Check if the file exists
                    data_path = os.path.join(folder_path, f"log_data{num+1}_{flow_pointer}.csv")
                    if not os.path.exists(data_path):
                        print(f"File {data_path} does not exist")
                        continue
                
                    print(f"Processing file: log_data{num+1}_{flow_pointer}.csv")

                    # read csv_log file
                    df = pd.read_csv(data_path)  

                    time_s_log_list = df['now_us'] if not df['now_us'].isnull().all() else None

                    cwnd_MB_log_list = df['cwnd_MB'] if not df['cwnd_MB'].isnull().all() else None

                    mss_log = df['mss'].iloc[0] if not df['mss'].isnull().all() else None

                    ssthresh_log = df['ssthresh_pkt'] if not df['ssthresh_pkt'].isnull().all() else None
                    ssthresh_MB_log_list = ssthresh_log * 1e-6 if ssthresh_log is not None else None

                    search_exit_s_log_list = df['now_exit_search_s'] if not df['now_exit_search_s'].isnull().all() else None

                    loss_time_s_log_list = df['now_s_loss'] if not df['now_s_loss'].isnull().all() else None

                    rto_time_s_log_list = df['now_s_rto'] if not df['now_s_rto'].isnull().all() else None

                    ecn_time_s_log_list = df['now_s_ecn'] if not df['now_s_ecn'].isnull().all() else None

                    after_idle_time_s_log_list = df['now_s_after_idle'] if not df['now_s_after_idle'].isnull().all() else None

                    srtt_s_log_list = df['srtt_s'] if not df['srtt_s'].isnull().all() else None

                    currack_log_list = df['curack'] if not df['curack'].isnull().all() else None

                    total_bytes_acked_MB_log_list = df['total_bytes_acked'] if not df['total_bytes_acked'].isnull().all() else None # calculated by sum of each_bytes_ack

                    each_delv_bytes_MB_log_list = df['each_delv_MB'] if not df['each_delv_MB'].isnull().all() else None

                    norm_values_list = df['norm'] if not df['norm'].isnull().all() else None

                    search_time_s_log_list = df['now_s_search'] if not df['now_s_search'].isnull().all() else None

                    send_next_list = df['tp_send_next'] if not df['tp_send_next'].isnull().all() else None

                    initial_seq_sent_list = df['tp_iss'] if not df['tp_iss'].isnull().all() else None

                    sent_bytes = send_next_list - initial_seq_sent_list if send_next_list is not None and initial_seq_sent_list is not None else None

                    sent_MB_list = sent_bytes * 1e-6 if sent_bytes is not None else None

                    curr_delv_window_MB_list = df['curr_delv_MB'] if not df['curr_delv_MB'].isnull().all() else None

                    prev_delv_window_MB_list = df['prev_delv_MB'] if not df['prev_delv_MB'].isnull().all() else None

                    # Check if there is negative value in norm_list, and replace that with 0
                    if norm_values_list is not None:
                        norm_values_list = [max(0, value) for value in norm_values_list]

                    # throughput calculation
                    throughputs = []
                    timestamps_thput = []
                    # Check if the pcap csv file exists
                    if os.path.exists(pcap_csv_path):
                        print(f"Processing pcap csv file for run {num+1} and flow pointer {flow_pointer}")
                        csv_file_path = os.path.join(pcap_csv_path, f"tcp_run_{num+1}.csv")

                        if os.path.exists(csv_file_path):
                            df = pd.read_csv(csv_file_path)

                            # Find the first row where the ack number is greater than 1000 (sync the time of pcap file and log file)
                            first_row = df[df['Ack number'] > 1000].iloc[0]

                            # Get the time value from the first row
                            time_first_ack = first_row['Time']

                            # remove the times before time_first_ack
                            df = df[df['Time'] >= time_first_ack]

                            df['Time'] = df['Time'] - time_first_ack

                            df_valid = df[(df["Source"] == SERVER_IP) & (df["retransmission"].isna())]
                            df_valid = df_valid.sort_values("Time")

                            start_time = df_valid["Time"].iloc[0]
                            end_time = start_time + INTERVAL

                            # Compute throughput in fixed intervals
                            while end_time <= df_valid["Time"].iloc[-1]:
                                window_data = df_valid.loc[(df_valid["Time"] >= start_time) & (df_valid["Time"] < end_time)]
                                if not window_data.empty:
                                    total_bytes = window_data["Length"].sum() * 8 * 1e-6
                                    throughput = total_bytes / INTERVAL
                                    throughputs.append(throughput)
                                    timestamps_thput.append(end_time)

                                # Move to next window
                                start_time = end_time
                                end_time = start_time + INTERVAL
                        else:
                            print(f"File {csv_file_path} does not exist")
                    else:
                        print(f"Directory {pcap_csv_path} does not exist")
                    # If throughputs is empty, set it to None
                    if not throughputs:
                        throughputs = None
                        timestamps_thput = None
                    else:
                        # Convert throughputs to numpy array
                        throughputs = np.array(throughputs)
                        timestamps_thput = np.array(timestamps_thput)

                    ################ Claculate delivery rate over time
                    # Convert time_us_log_list to numpy array
                    time_s_log_list = np.array(time_s_log_list)
                    # Convert total_bytes_acked_MB_log_list to numpy array
                    total_bytes_acked_MB_log_list = np.array(total_bytes_acked_MB_log_list)
                    # Convert currack_log_list to numpy array
                    currack_log_list = np.array(currack_log_list) * 1e-6
                    #convert srtt to numpy array
                    srtt_s_log_list = np.array(srtt_s_log_list)
                            

                    delivery_rate_per_ack, start_index, time_cal_delv_rates = calculate_delivery_rate_per_ack(total_bytes_acked_MB_log_list, time_s_log_list, srtt_s_log_list)            
                                
                    ################ plotting ##########################
                    # remove none values from search_exit
                    if search_exit_s_log_list is not None:
                        search_exit_s_log_list = [x for x in search_exit_s_log_list if x is not None]
                    # # add very small jitter to search_exit_s_log_list to avoid overlapping
                    # if search_exit_s_log_list is not None:
                    #     for i in range(len(search_exit_s_log_list)):
                    #         if search_exit_s_log_list[i] is not None:
                    #             search_exit_s_log_list[i] += 0.03

                    # keep the first large sshtresh to the smaller value to can dshow on plot
                    initial_ssthresh = ssthresh_MB_log_list[0]
                    max_cwnd = max(cwnd_MB_log_list)
                    # for i in range(len(ssthresh_MB_log_list)):
                    #     if ssthresh_MB_log_list[i] == initial_ssthresh:
                    #         ssthresh_MB_log_list[i] = max_cwnd + 900
                            
                    # plot cwnd and ssthresh on same graph
                    plt.figure(figsize=(12, 6))

                    # Plot cwnd and ssthresh
                    plt.plot(time_s_log_list, cwnd_MB_log_list, label='cwnd', color='blue', marker='o')
                    plt.plot(time_s_log_list, ssthresh_MB_log_list, label='ssthresh', color='orange', marker='x')

                    # Plot each event type using vlines
                    # Only first one gets a label (legend deduplication)
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                    plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                    plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                    plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                    # Final plot styling
                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Size (MB)', fontsize=18)
                    plt.title('cwnd and ssthresh over time', fontsize=20)
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.ylim(-0.05, max_cwnd * 1.5)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                    plt.tight_layout()

                    # Save figure
                    output_filename = os.path.join(fig_path, f"cwnd_ssthresh_{num+1}_{flow_pointer}_zoom1.png")
                    plt.savefig(output_filename)
                    plt.close()

                    # plot delivery rate over time
                    plt.figure(figsize=(12, 6))
                    plt.plot(time_cal_delv_rates, delivery_rate_per_ack, label='Delivery Rate', color='blue', marker='o')
                    # add search exit time
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                    plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                    plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                    plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Delivery Rate (MB/s)', fontsize=18)
                    plt.title('Delivery Rate over time')
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)

                    # plt.grid()
                    plt.savefig(os.path.join(fig_path, f"delivery_rate_{num+1}_{flow_pointer}_zoom1.png"))
                    plt.close()
            
                    # plot srtt over time
                    plt.figure(figsize=(12, 6))
                    plt.plot(time_s_log_list, srtt_s_log_list, label='srtt', color='blue', marker='o')
                    # add search exit time
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                    plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                    plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                    plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('srtt (s)', fontsize=18)
                    plt.title('srtt over time')
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                    plt.savefig(os.path.join(fig_path, f"srtt_{num+1}_{flow_pointer}_zoom1.png"))
                    plt.close()

                    # plot curr_delv_window and twice prev_delv_window over time
                    plt.figure(figsize=(12, 6))
                    plt.plot(search_time_s_log_list, curr_delv_window_MB_list, label='curr_delv_window', color='blue', marker='o')
                    plt.plot(search_time_s_log_list, prev_delv_window_MB_list * 2, label='twice prev_delv_window', color='g', marker='o')
                    
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                    plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                    plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                    plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Delivery Window (MB)', fontsize=18)
                    plt.title('Delivery Window over time')
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                    plt.savefig(os.path.join(fig_path, f"delivery_window_{num+1}_{flow_pointer}_zoom1.png"))
                    plt.close()
                    
                    # plot norm over search_time
                    if norm_values_list is not None:
                        plt.figure(figsize=(12, 6))
                        plt.plot(search_time_s_log_list, norm_values_list, label='norm', color='blue', marker='o')
                        plt.axhline(y=35, color='c', linestyle='--', label='norm threshold')
                            
                        plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                        plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                        plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                        plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                        plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)
                        

                        plt.xlabel('Time (s)', fontsize=18)
                        plt.ylabel('norm', fontsize=18)
                        plt.title('norm over time')
                        plt.legend(loc='lower right')
                        plt.xticks(fontsize=16)
                        plt.yticks(fontsize=16)
                        plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                        plt.savefig(os.path.join(fig_path, f"norm_{num+1}_{flow_pointer}_zoom1.png"))
                        plt.close()
            

                    # plot throughput from pcap on server        
                    if throughputs is not None:
                        # Plot throughput
                        plt.figure(figsize=(12, 6))
                        plt.plot(timestamps_thput, throughputs, label='Throughput', color='blue', marker='o')
                        # add search exit time
                        if search_exit_s_log_list is not None:
                            for i in range(len(search_exit_s_log_list)):
                                if search_exit_s_log_list[i] is not None:
                                    plt.axvline(x=search_exit_s_log_list[i], color='g', linestyle='--', label='search exit time' if i == 0 else "")
                        # plot loss times
                        if loss_time_s_log_list is not None:
                            for i in range(len(loss_time_s_log_list)):
                                if loss_time_s_log_list[i] is not None:
                                    plt.axvline(x=loss_time_s_log_list[i], color='r', linestyle='--', label='loss time' if i == 0 else "")
                        # plot rto times
                        if rto_time_s_log_list is not None:
                            for i in range(len(rto_time_s_log_list)):
                                if rto_time_s_log_list[i] is not None:
                                    plt.axvline(x=rto_time_s_log_list[i], color='m', linestyle='--', label='RTO time' if i == 0 else "")
                        # plot ecn times
                        if ecn_time_s_log_list is not None:
                            for i in range(len(ecn_time_s_log_list)):
                                if ecn_time_s_log_list[i] is not None:
                                    plt.axvline(x=ecn_time_s_log_list[i], color='purple', linestyle='--', label='ECN time' if i == 0 else "")
                        # plot after idle times
                        if after_idle_time_s_log_list is not None:
                            for i in range(len(after_idle_time_s_log_list)):
                                if after_idle_time_s_log_list[i] is not None:
                                    plt.axvline(x=after_idle_time_s_log_list[i], color='lightgray', linestyle='--', label='after idle time' if i == 0 else "")
                        plt.xlabel('Time (s)', fontsize=18)
                        plt.ylabel('Throughput (MB/s)', fontsize=18)
                        plt.title('Throughput over time')
                        plt.legend(loc='lower right')
                        plt.xticks(fontsize=16)
                        plt.yticks(fontsize=16)
                        plt.xlim(-1, 50)
                        # plt.grid()
                        plt.savefig(os.path.join(fig_path, f"throughput_{num+1}_{flow_pointer}.png"))
                        plt.close()
                        print("Plots saved successfully.")

                        # Plot sent bytes and total bytes acked over time 
                        plt.figure(figsize=(12, 6)) 
                        if sent_MB_list is not None:
                            plt.plot(time_s_log_list, sent_MB_list, label='Sent Bytes', color='blue', marker='o')
                        if total_bytes_acked_MB_log_list is not None:
                            plt.plot(time_s_log_list, total_bytes_acked_MB_log_list, label='Bytes Acked', color='green', marker='x')
                        # add search exit time
                        plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                        plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                        plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                        plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                        plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                        plt.xlabel('Time (s)', fontsize=18)
                        plt.ylabel('Bytes (MB)', fontsize=18)
                        plt.title('Total Sent Bytes and Total Bytes Acked over time')
                        plt.legend(loc='lower right')
                        plt.xticks(fontsize=16)
                        plt.yticks(fontsize=16)
                        plt.xlim(-1, 50)
                        # plt.grid()
                        plt.savefig(os.path.join(fig_path, f"sent_total_acked_{num+1}_{flow_pointer}.png"))
                        plt.close()

    if client_data_path:

        client_log_files = [f for f in os.listdir(client_data_path) if f.startswith("Tester") and f.endswith(".txt")]
        client_log_files.sort()

        for client_log_file in client_log_files:
            client_log_path = os.path.join(client_data_path, client_log_file)
            if not os.path.exists(client_log_path):
                print(f"Client log file {client_log_path} does not exist")
                continue
            
            print(f"Processing client log file: {client_log_file}")
            client_info = parse_client_log_file(client_log_path)

            # Extract times and bitrates
            times = client_info['times']
            bitrates = client_info['bitrates']
            # convert bitrates to Mbps
            bitrates = bitrates / 1000  # Convert to kbps

            # Plot bitrate over time
            plt.figure(figsize=(12, 6))
            plt.plot(times, bitrates, label='Bitrate', color='blue', marker='o', linewidth=0.5)
            plt.xlabel('Time (s)', fontsize=18)
            plt.ylabel('Bitrate (Mbps)', fontsize=18)
            plt.title(f'Bitrate over time for {client_log_file}')
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)
            plt.savefig(os.path.join(fig_path, f"bitrate_{client_log_file}.png"))
            plt.close()

            # plot cdf of bitrates
            bitrates_sorted = np.sort(bitrates)
            cdf_bitrate = np.arange(1, len(bitrates_sorted) + 1) / len(bitrates_sorted)

            plt.figure(figsize=(12, 6))
            plt.plot(bitrates_sorted, cdf_bitrate, marker="o",label='CDF of Bitrate', color='darkred', linewidth=0.5)
            plt.xlabel('Bitrate (Mbps)', fontsize=18)
            plt.ylabel('CDF', fontsize=18)
            plt.title(f'CDF of Bitrate for {client_log_file}')
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)
            plt.savefig(os.path.join(fig_path, f"cdf_bitrate_{client_log_file}.png"))
            plt.close()

            # plot resolution over time
            resolutions = client_info['resolutions']
            unique_resolutions = np.unique(resolutions)
            resolution_colors = {
                '360p': 'blue',
                '480p': 'green',
                '720p': 'orange',
                '1080p': 'red',
                '2K': 'purple',
                '4K': 'brown'
            }
            plt.figure(figsize=(12, 6))
            for res in unique_resolutions:
                res_times = times[resolutions == res]
                res_bitrates = bitrates[resolutions == res]
                plt.plot(res_times, res_bitrates, label=res, color=resolution_colors.get(res, 'black'), marker='o', linestyle='')
            plt.xlabel('Time (s)', fontsize=18)
            plt.ylabel('Bitrate (Mbps)', fontsize=18)
            plt.title(f'Bitrate by Resolution over time for {client_log_file}')
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)
            plt.legend(title='Resolution', fontsize=12)
            plt.savefig(os.path.join(fig_path, f"bitrate_resolution_{client_log_file}.png"))
            plt.close()

            # plot cdf of resolutions
            # Define proper resolution order
            resolution_order = ['360p', '480p', '720p', '1080p', '2K', '4K']
            res_label_to_value = {label: i for i, label in enumerate(resolution_order)}

            # Count and sort
            resolution_counts = pd.Series(resolutions).value_counts()
            resolution_counts = resolution_counts.loc[[res for res in resolution_order if res in resolution_counts]]

            # Compute CDF
            resolution_values = resolution_counts.values
            resolution_labels = resolution_counts.index
            resolution_cdf = np.cumsum(resolution_values) / np.sum(resolution_values)

            # Plot
            plt.figure(figsize=(12, 6))
            plt.plot(resolution_labels, resolution_cdf, marker='o', color='darkgreen', linewidth=0.5, label='CDF of Resolution')
            plt.xlabel('Resolution', fontsize=18)
            plt.ylabel('CDF', fontsize=18)
            plt.title(f'CDF of Resolution for {client_log_file}', fontsize=20)
            plt.xticks(rotation=45, fontsize=16)
            plt.yticks(fontsize=16)
            plt.tight_layout()
            plt.savefig(os.path.join(fig_path, f"cdf_resolution_{client_log_file}.png"))
            plt.close()



            
    ######################################################################################################                
    if CRASH_TEST_RESULT:

        output_csv_folder = os.path.join(server_data_path, "csv_server")
        os.makedirs(output_csv_folder, exist_ok=True)

        # Extract start and end time of video streaming from client file
        client_times = extract_client_times(client_data_path)

        log_files = [f for f in os.listdir(server_data_path) if f.endswith("_ccrg.log")]
        
        sortef_log_files = sorted(log_files, key=lambda x: int(re.search(r'(\d+)', x).group(1)))
        
        # Process each log file
        for log_file, (start_time, end_time) in zip(sortef_log_files, client_times):
            full_path = os.path.join(server_data_path, log_file)
            flows = parse_ccrg_log(full_path)
            test_id = log_file.split("_")[0]

            for flow_ptr, records in flows.items():
                if len(records) >= 500:
                    df = pd.DataFrame(records)
                    
                    # Add start and end time as new columns
                    df["start_time"] = start_time.strftime("%Y-%m-%d %H:%M:%S")
                    df["end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    ############### Find the start time and start from zero #########
                    # Parse start_time and log_time of the first row
                    start_dt = datetime.strptime(df['start_time'].iloc[0], "%Y-%m-%d %H:%M:%S")
                    first_log_time_str = df['log_time'].iloc[0]
                    
                    # Create datetime for log_time using start_time's date
                    first_log_dt = datetime.combine(start_dt.date(), datetime.strptime(first_log_time_str, "%H:%M:%S").time())

                    # Compute time delta in microseconds
                    delta_us = int((first_log_dt - start_dt).total_seconds() * 1_000_000)

                    # Get now_at_start
                    first_now = df['now'].iloc[0]
                    now_at_start = first_now - delta_us

                    # Add columns
                    df['now_at_start'] = now_at_start
                    df['now_from_zero_us'] = df['now'] - now_at_start
                    ##############################################################

                    df["rate_Mbps"] = (df["delta_bytes"] * 8) / df["rtt_us"]
                    df["rate_Mbps_one_bin"] = (df["delta_bytes_one_bin"] * 8) / df["rtt_us"]

                    csv_path = os.path.join(output_csv_folder, f"{test_id}_{flow_ptr}.csv")

                    df.to_csv(csv_path, index=False)


                    # if df['now_from_zero_us'].iloc[0] < 0:
                    #     continue
                    # else:
                    # plot rate_Mbps
                    plt.figure(figsize=(12, 6))
                    plt.plot(df['now_from_zero_us'] / 1_000_000, df['rate_Mbps'], label='Rate (Mbps)', color='blue', marker='o')
                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Rate (Mbps)', fontsize=18)
                    plt.title(f'Rate (based on window values) over time for {test_id} - {flow_ptr}')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.savefig(os.path.join(fig_path, f"{test_id}_{flow_ptr}_exitrate_win.png"))
                    plt.close()

                    # plot rate_Mbps based on one bin values
                    plt.figure(figsize=(12, 6))
                    plt.plot(df['now_from_zero_us'] / 1_000_000, df['rate_Mbps_one_bin'], label='Rate (Mbps)', color='blue', marker='o')
                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Rate (Mbps)', fontsize=18)
                    plt.title(f'Rate (based on one bin values) over time for {test_id} - {flow_ptr}')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.savefig(os.path.join(fig_path, f"{test_id}_{flow_ptr}_exitrate_bin.png"))
                    plt.close()


if Linux_RESULT:
    
    if SEARCH_RESULT:
        folder_path = os.path.join(server_data_path, FOLDER_PATH)

        if os.path.isdir(folder_path):
            print("Processing:", folder_path)
            # count the number of files in the directory
            # num_files = len([name for name in os.listdir(folder_path) if name.endswith(".csv")])
            num_files = []
            for name in os.listdir(folder_path):
                if name.startswith("log_data") and name.endswith(".csv"):
                    match = re.search(r'log_data(\d+)_', name)
                    if match:
                        num_files.append(int(match.group(1)))

            # extract flow pointer part from filename (log_data{num}_{flow_pointer}.csv)
            flow_pointers = []
            for name in os.listdir(folder_path):
                if name.startswith("log_data") and name.endswith(".csv"):
                    match = re.search(r'_(0x[0-9a-fA-F]+)\.csv', name)
                    if match:
                        flow_pointer = match.group(1)
                        flow_pointers.append(flow_pointer)

            for num in num_files:
                for flow_pointer in flow_pointers:

                    time_s_log_list = []
                    cwnd_MB_log_list = []
                    ssthresh_MB_log_list = []
                    # mss_log = None
                    search_exit_s_log_list = []
                    retrans_log_list = []
                    loss_time_s_log_list = []
                    rtt_s_log_list = []
                    total_bytes_acked_MB_log_list = []
                    norm_values_list = []
                    search_time_s_log_list = []
                    each_delv_bytes_MB_log_list = []
                    curr_delv_window_MB_list = []
                    prev_delv_window_MB_list = []
                    rate_app_limited_log_list = []

                    # Check if the file exists
                    data_path = os.path.join(folder_path, f"log_data{num}_{flow_pointer}.csv")
                    if not os.path.exists(data_path):
                        print(f"File {data_path} does not exist")
                        continue
                
                    print(f"Processing file: log_data{num}_{flow_pointer}.csv")

                    # read csv_log file
                    df = pd.read_csv(data_path)  

                    time_s_log_list = df['start_time_zero_s'] if not df['start_time_zero_s'].isnull().all() else None

                    cwnd_MB_log_list = df['cwnd_MB'] if not df['cwnd_MB'].isnull().all() else None

                    # mss_log = df['mss'].iloc[0] if not df['mss'].isnull().all() else None

                    ssthresh_log = df['ssthresh_pkt'] if not df['ssthresh_pkt'].isnull().all() else None
                    ssthresh_MB_log_list = ssthresh_log * 1448 * 1e-6 if ssthresh_log is not None else None

                    search_exit_s_log_list = df['search_ex_time_s'] if not df['search_ex_time_s'].isnull().all() else None

                    retrans_log_list = df['total_retrans_pkt'] if not df['total_retrans_pkt'].isnull().all() else None

                    loss_log_list = df['lost_pkt'] if not df['lost_pkt'].isnull().all() else None

                    rtt_s_log_list = df['rtt_s'] if not df['rtt_s'].isnull().all() else None

                    total_bytes_acked_MB_log_list = df['total_byte_acked'] if not df['total_byte_acked'].isnull().all() else None

                    each_delv_bytes_MB_log_list = df['each_delv_MB'] if not df['each_delv_MB'].isnull().all() else None

                    norm_values_list = df['norm'] if not df['norm'].isnull().all() else None

                    search_time_s_log_list = df['search_time_s'] if not df['search_time_s'].isnull().all() else None

                    curr_delv_window_MB_list = df['current_wind_MB'] if not df['current_wind_MB'].isnull().all() else None

                    prev_delv_window_MB_list = df['prev_wind_MB'] if not df['prev_wind_MB'].isnull().all() else None

                    rate_app_limited_log_list = df['rate_app_limited'] if not df['rate_app_limited'].isnull().all() else None

                    # Check if there is negative value in norm_list, and replace that with 0
                    if norm_values_list is not None:
                        norm_values_list = [max(0, value) for value in norm_values_list]
                    #check if there is very large value in norm_list, and replace that with 0
                    if norm_values_list is not None:
                        norm_values_list = [value if value < 1000 else 0 for value in norm_values_list]

                    # find the correspoding time when app limited is 1
                    app_limited_times = []
                    if rate_app_limited_log_list is not None:
                        for i, rate in enumerate(rate_app_limited_log_list):
                            if rate > 0:
                                if time_s_log_list is not None and i < len(time_s_log_list):
                                    app_limited_times.append(time_s_log_list[i])
                                else:
                                    app_limited_times.append(None)
                    else:
                        app_limited_times = None

                    # find the correspoding time when retransmission is not zero for the first time and make sure that ssthresh does not back to the initial value after that
                    initial_ssthresh = ssthresh_MB_log_list[0] if ssthresh_MB_log_list is not None else None
                    target_time = None
                    loss_time_list =[]

                    def same(a, b, eps=1e-9):          # helper for float equality
                        return math.isclose(a, b, abs_tol=eps)

                    last_initial_idx = -1              # default: never saw it again
                    for idx, val in enumerate(ssthresh_MB_log_list):
                        if same(val, initial_ssthresh):
                            last_initial_idx = idx     # keep updating until the last one

                    # ----------------------------------------------------------------------
                    # 2) scan forward *after* that index for the first retransmission > 0
                    target_time = None
                    for i in range(last_initial_idx + 1, len(retrans_log_list)):
                        if retrans_log_list[i] > 0:
                            target_time = time_s_log_list[i]
                            break                      # <-- first qualifying point found
                    # ----------------------------------------------------------------------

                    loss_time_list.append(target_time if target_time is not None else None)

                    # throughput calculation
                    throughputs = []
                    timestamps_thput = []
                    # Check if the pcap csv file exists
                    if os.path.exists(pcap_csv_path):
                        print(f"Processing pcap csv file for run {num} and flow pointer {flow_pointer}")
                        csv_file_path = os.path.join(pcap_csv_path, f"tcp_run_{num}.csv")

                        if os.path.exists(csv_file_path):
                            df = pd.read_csv(csv_file_path)

                            # Find the first row where the ack number is greater than 1000 (sync the time of pcap file and log file)
                            first_row = df[df['Ack number'] > 1000].iloc[0]

                            # Get the time value from the first row
                            time_first_ack = first_row['Time']

                            # remove the times before time_first_ack
                            df = df[df['Time'] >= time_first_ack]

                            df['Time'] = df['Time'] - time_first_ack

                            df_valid = df[(df["Source"] == SERVER_IP) & (df["retransmission"].isna())]
                            df_valid = df_valid.sort_values("Time")

                            start_time = df_valid["Time"].iloc[0]
                            end_time = start_time + INTERVAL

                            # Compute throughput in fixed intervals
                            while end_time <= df_valid["Time"].iloc[-1]:
                                window_data = df_valid.loc[(df_valid["Time"] >= start_time) & (df_valid["Time"] < end_time)]
                                if not window_data.empty:
                                    total_bytes = window_data["Length"].sum() * 8 * 1e-6
                                    throughput = total_bytes / INTERVAL
                                    throughputs.append(throughput)
                                    timestamps_thput.append(end_time)

                                # Move to next window
                                start_time = end_time
                                end_time = start_time + INTERVAL
                        else:
                            print(f"File {csv_file_path} does not exist")
                    else:
                        print(f"Directory {pcap_csv_path} does not exist")
                    # If throughputs is empty, set it to None
                    if not throughputs:
                        throughputs = None
                        timestamps_thput = None
                    else:
                        # Convert throughputs to numpy array
                        throughputs = np.array(throughputs)
                        timestamps_thput = np.array(timestamps_thput)

                    ################ Claculate delivery rate over time
                    # Convert time_us_log_list to numpy array
                    time_s_log_list = np.array(time_s_log_list)
                    # Convert total_bytes_acked_MB_log_list to numpy array
                    total_bytes_acked_MB_log_list = np.array(total_bytes_acked_MB_log_list)
                    #convert rtt to numpy array
                    rtt_s_log_list = np.array(rtt_s_log_list)
                            

                    delivery_rate_per_ack, start_index, time_cal_delv_rates = calculate_delivery_rate_per_ack(total_bytes_acked_MB_log_list, time_s_log_list, rtt_s_log_list)            
                                
                    ################ plotting ##########################
                    # remove none values from search_exit
                    if search_exit_s_log_list is not None:
                        search_exit_s_log_list = [x for x in search_exit_s_log_list if x is not None]
                    # # add very small jitter to search_exit_s_log_list to avoid overlapping
                    # if search_exit_s_log_list is not None:
                    #     for i in range(len(search_exit_s_log_list)):
                    #         if search_exit_s_log_list[i] is not None:
                    #             search_exit_s_log_list[i] += 0.03

                    # keep the first large sshtresh to the smaller value to can dshow on plot
                    initial_ssthresh = ssthresh_MB_log_list[0]
                    max_cwnd = max(cwnd_MB_log_list)
                    # for i in range(len(ssthresh_MB_log_list)):
                    #     if ssthresh_MB_log_list[i] == initial_ssthresh:
                    #         ssthresh_MB_log_list[i] = max_cwnd + 900
                            
                    # plot cwnd and ssthresh on same graph
                    plt.figure(figsize=(12, 6))

                    # Plot cwnd and ssthresh
                    plt.plot(time_s_log_list, cwnd_MB_log_list, label='cwnd', color='blue', marker='o')
                    plt.plot(time_s_log_list, ssthresh_MB_log_list, label='ssthresh', color='orange', marker='x')

                    # Plot each event type using vlines
                    # Only first one gets a label (legend deduplication)
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(loss_time_list, 'bisque', 'loss time',1)
                    plot_vlines(app_limited_times, 'purple', 'app limited time', 1)



                    # Final plot styling
                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Size (MB)', fontsize=18)
                    plt.title('cwnd and ssthresh over time', fontsize=20)
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.ylim(-0.05, max_cwnd * 1.5)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                    plt.tight_layout()

                    # Save figure
                    output_filename = os.path.join(fig_path, f"cwnd_ssthresh_{num}_{flow_pointer}_zoom1.png")
                    plt.savefig(output_filename)
                    plt.close()

                    # plot delivery rate over time
                    plt.figure(figsize=(12, 6))
                    plt.plot(time_cal_delv_rates, delivery_rate_per_ack, label='Delivery Rate', color='blue', marker='o')
                    # add search exit time
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(loss_time_list, 'bisque', 'loss time',1)
                    plot_vlines(app_limited_times, 'purple', 'app limited time', 1)


                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Delivery Rate (MB/s)', fontsize=18)
                    plt.title('Delivery Rate over time')
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)

                    # plt.grid()
                    plt.savefig(os.path.join(fig_path, f"delivery_rate_{num}_{flow_pointer}_zoom1.png"))
                    plt.close()
            
                    # plot srtt over time
                    plt.figure(figsize=(12, 6))
                    plt.plot(time_s_log_list, rtt_s_log_list, label='rtt', color='blue', marker='o')
                    # add search exit time
                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(loss_time_list, 'bisque', 'loss time',1)
                    plot_vlines(app_limited_times, 'purple', 'app limited time', 1)

                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('rtt (s)', fontsize=18)
                    plt.title('rtt over time')
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                    plt.savefig(os.path.join(fig_path, f"rtt_{num}_{flow_pointer}_zoom1.png"))
                    plt.close()

                    # plot curr_delv_window and twice prev_delv_window over time
                    plt.figure(figsize=(12, 6))
                    plt.plot(search_time_s_log_list, curr_delv_window_MB_list, label='curr_delv_window', color='blue', marker='o')
                    plt.plot(search_time_s_log_list, prev_delv_window_MB_list * 2, label='twice prev_delv_window', color='g', marker='o')

                    plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                    plot_vlines(loss_time_list, 'bisque', 'loss time',1)
                    plot_vlines(app_limited_times, 'purple', 'app limited time', 1)
                    
                    plt.xlabel('Time (s)', fontsize=18)
                    plt.ylabel('Delivery Window (MB)', fontsize=18)
                    plt.title('Delivery Window over time')
                    plt.legend(loc='lower right')
                    plt.xticks(fontsize=16)
                    plt.yticks(fontsize=16)
                    plt.ylim(-0.01, max([max(curr_delv_window_MB_list), max(prev_delv_window_MB_list*2)]) * 1.5)
                    plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                    plt.savefig(os.path.join(fig_path, f"delivery_window_{num}_{flow_pointer}_zoom1.png"))
                    plt.close()
                    
                    # plot norm over search_time
                    if norm_values_list is not None:
                        plt.figure(figsize=(12, 6))
                        plt.plot(search_time_s_log_list, norm_values_list, label='norm', color='blue', marker='o')
                        plt.axhline(y=0.35, color='c', linestyle='--', label='norm threshold')
                        plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                        plot_vlines(loss_time_list, 'bisque', 'loss time',1)
                        plot_vlines(app_limited_times, 'purple', 'app limited time', 1)
                        
                        plt.xlabel('Time (s)', fontsize=18)
                        plt.ylabel('norm', fontsize=18)
                        plt.title('norm over time')
                        plt.legend(loc='lower right')
                        plt.xticks(fontsize=16)
                        plt.yticks(fontsize=16)
                        plt.xlim(-0.05, search_exit_s_log_list[0] + 1)
                        plt.savefig(os.path.join(fig_path, f"norm_{num}_{flow_pointer}_zoom1.png"))
                        plt.close()
            

                    # plot throughput from pcap on server        
                    if throughputs is not None:
                        # Plot throughput
                        plt.figure(figsize=(12, 6))
                        plt.plot(timestamps_thput, throughputs, label='Throughput', color='blue', marker='o')
                        # add search exit time
                        plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                        plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                        plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                        plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                        plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                        plt.xlabel('Time (s)', fontsize=18)
                        plt.ylabel('Throughput (MB/s)', fontsize=18)
                        plt.title('Throughput over time')
                        plt.legend(loc='lower right')
                        plt.xticks(fontsize=16)
                        plt.yticks(fontsize=16)
                        plt.xlim(-1, 50)
                        # plt.grid()
                        plt.savefig(os.path.join(fig_path, f"throughput_{num}_{flow_pointer}.png"))
                        plt.close()
                        print("Plots saved successfully.")

                        # Plot sent bytes and total bytes acked over time 
                        # plt.figure(figsize=(12, 6)) 
                        # if sent_MB_list is not None:
                        #     plt.plot(time_s_log_list, sent_MB_list, label='Sent Bytes', color='blue', marker='o')
                        # if total_bytes_acked_MB_log_list is not None:
                        #     plt.plot(time_s_log_list, total_bytes_acked_MB_log_list, label='Bytes Acked', color='green', marker='x')
                        # # add search exit time
                        # plot_vlines(search_exit_s_log_list, 'green', 'search exit time', 3)                
                        # plot_vlines(after_idle_time_s_log_list, 'lightgray', 'after idle time', 1)
                        # plot_vlines(loss_time_s_log_list, 'red', 'loss time',1)
                        # plot_vlines(rto_time_s_log_list, 'magenta', 'RTO time', 1)
                        # plot_vlines(ecn_time_s_log_list, 'purple', 'ECN time', 1)

                        # plt.xlabel('Time (s)', fontsize=18)
                        # plt.ylabel('Bytes (MB)', fontsize=18)
                        # plt.title('Total Sent Bytes and Total Bytes Acked over time')
                        # plt.legend(loc='lower right')
                        # plt.xticks(fontsize=16)
                        # plt.yticks(fontsize=16)
                        # plt.xlim(-1, 50)
                        # # plt.grid()
                        # plt.savefig(os.path.join(fig_path, f"sent_total_acked_{num}_{flow_pointer}.png"))
                        # plt.close()

    if client_data_path:

        client_log_files = [f for f in os.listdir(client_data_path) if f.startswith("Tester") and f.endswith(".txt")]
        client_log_files.sort()

        for client_log_file in client_log_files:
            client_log_path = os.path.join(client_data_path, client_log_file)
            if not os.path.exists(client_log_path):
                print(f"Client log file {client_log_path} does not exist")
                continue
            
            print(f"Processing client log file: {client_log_file}")
            client_info = parse_client_log_file(client_log_path)

            # Extract times and bitrates
            times = client_info['times']
            bitrates = client_info['bitrates']
            # convert bitrates to Mbps
            bitrates = bitrates / 1000  # Convert to kbps

            # Plot bitrate over time
            plt.figure(figsize=(12, 6))
            plt.plot(times, bitrates, label='Bitrate', color='blue', marker='o', linewidth=0.5)
            plt.xlabel('Time (s)', fontsize=18)
            plt.ylabel('Bitrate (Mbps)', fontsize=18)
            plt.title(f'Bitrate over time for {client_log_file}')
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)
            plt.savefig(os.path.join(fig_path, f"bitrate_{client_log_file}.png"))
            plt.close()

            # plot cdf of bitrates
            bitrates_sorted = np.sort(bitrates)
            cdf_bitrate = np.arange(1, len(bitrates_sorted) + 1) / len(bitrates_sorted)

            plt.figure(figsize=(12, 6))
            plt.plot(bitrates_sorted, cdf_bitrate, marker="o",label='CDF of Bitrate', color='darkred', linewidth=0.5)
            plt.xlabel('Bitrate (Mbps)', fontsize=18)
            plt.ylabel('CDF', fontsize=18)
            plt.title(f'CDF of Bitrate for {client_log_file}')
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)
            plt.savefig(os.path.join(fig_path, f"cdf_bitrate_{client_log_file}.png"))
            plt.close()

            # plot resolution over time
            resolutions = client_info['resolutions']
            unique_resolutions = np.unique(resolutions)
            resolution_colors = {
                '360p': 'blue',
                '480p': 'green',
                '720p': 'orange',
                '1080p': 'red',
                '2K': 'purple',
                '4K': 'brown'
            }
            plt.figure(figsize=(12, 6))
            for res in unique_resolutions:
                res_times = times[resolutions == res]
                res_bitrates = bitrates[resolutions == res]
                plt.plot(res_times, res_bitrates, label=res, color=resolution_colors.get(res, 'black'), marker='o', linestyle='')
            plt.xlabel('Time (s)', fontsize=18)
            plt.ylabel('Bitrate (Mbps)', fontsize=18)
            plt.title(f'Bitrate by Resolution over time for {client_log_file}')
            plt.xticks(fontsize=16)
            plt.yticks(fontsize=16)
            plt.legend(title='Resolution', fontsize=12)
            plt.savefig(os.path.join(fig_path, f"bitrate_resolution_{client_log_file}.png"))
            plt.close()

            # plot cdf of resolutions
            # Define proper resolution order
            resolution_order = ['360p', '480p', '720p', '1080p', '2K', '4K']
            res_label_to_value = {label: i for i, label in enumerate(resolution_order)}

            # Count and sort
            resolution_counts = pd.Series(resolutions).value_counts()
            resolution_counts = resolution_counts.loc[[res for res in resolution_order if res in resolution_counts]]

            # Compute CDF
            resolution_values = resolution_counts.values
            resolution_labels = resolution_counts.index
            resolution_cdf = np.cumsum(resolution_values) / np.sum(resolution_values)

            # Plot
            plt.figure(figsize=(12, 6))
            plt.plot(resolution_labels, resolution_cdf, marker='o', color='darkgreen', linewidth=0.5, label='CDF of Resolution')
            plt.xlabel('Resolution', fontsize=18)
            plt.ylabel('CDF', fontsize=18)
            plt.title(f'CDF of Resolution for {client_log_file}', fontsize=20)
            plt.xticks(rotation=45, fontsize=16)
            plt.yticks(fontsize=16)
            plt.tight_layout()
            plt.savefig(os.path.join(fig_path, f"cdf_resolution_{client_log_file}.png"))
            plt.close()




        


                    

                