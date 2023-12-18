from bcc import BPF
import socket
import struct 
import ctypes as ct

def main():
    with open("bpf_firewall.c") as f:
        bpf_program = f.read()
    b = BPF(text=bpf_program)
    b.attach_xdp("wlp5s0", b.load_func(
        "xdp_firwall", BPF.XDP
    ))
    allowed_ips = b["allowed_ips"]

    ips = [

    ]

    for ip in ips:
            unpack_ip = struct.unpack("I", socket.inet_aton(ip))[0]
            allowed_ips[ct.c_uint(unpack_ip)] = ct.c_uint(1)
    
    try:
        print("Attaching XDP program ... Press Ctrl+C to exit")
        b.trace_print()
    except:
        pass
    
    b.remove_xdp("wlp5s0")


if __name__ == "__main__":
    main()
    