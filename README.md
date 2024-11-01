# Setting Up a High-Availability Metasploit RPC Server (`msgrpc`) Environment with HAProxy, SSL, and Keepalived on Ubuntu

![image](https://github.com/user-attachments/assets/52aaad4b-1f78-4d7f-8796-565a63d96ca7)

## Introduction

In penetration testing and security operations, the Metasploit Framework is a powerful tool used by security professionals to identify, exploit, and assess vulnerabilities within systems. To scale Metasploit's capabilities for larger teams or automated workflows, setting up its Remote Procedure Call (RPC) server (`msgrpc`) with high availability, load balancing, and secure access is essential. This guide walks you through configuring an `msgrpc` environment with HAProxy for load balancing, SSL for secure communication, and Keepalived for failover, ensuring resilience, performance, and security.

This setup enables teams to use Metasploit’s RPC API across multiple backend instances, offering redundancy and seamless failover if a server becomes unavailable. By configuring `msgrpc` and HAProxy as Ubuntu services, we enable them to start automatically, ensuring reliability. The addition of SSL secures sensitive data during transit, while session persistence maintains consistency for users interacting with the same backend server.

The article includes step-by-step instructions, best practices for secure configuration, and testing commands to verify the setup. By following this guide, you'll achieve a robust, scalable, and secure deployment for `msgrpc` services that meets production standards and minimizes downtime.

---

## Objectives

The key goals of this guide are:

1. **Automate Metasploit RPC (`msgrpc`) Startup**: Configure `msgrpc` as a root service on Ubuntu, enabling automatic startup on system boot.
2. **Implement HAProxy for HTTPS Load Balancing and Session Handling**: Configure HAProxy with SSL encryption, load balancing, and session persistence, directing traffic to multiple backend servers.
3. **Ensure High Availability with Keepalived**: Set up Keepalived to create a floating IP that can fail over between HAProxy instances in case of server downtime.
4. **Test and Secure the Configuration**: Verify the setup using `curl` commands to interact with the `msgrpc` API and apply security hardening techniques to safeguard the deployment.

---

## Security Requirements

Security is paramount in a Metasploit RPC deployment, as it involves sensitive operations, credentials, and network access. This setup includes several security requirements and recommendations to ensure secure and reliable operation:

1. **Use Strong Authentication for `msgrpc`**:
   - Configure a secure password for `msgrpc` with sufficient complexity to avoid unauthorized access.
   - Regularly rotate credentials and consider using a secure vault to store them.

2. **Enable SSL/TLS Encryption**:
   - Use SSL/TLS to encrypt communications between clients and HAProxy, protecting sensitive data in transit.
   - Obtain a trusted SSL certificate for production environments from a Certificate Authority (CA). For internal testing, self-signed certificates are acceptable.

3. **Restrict Network Access**:
   - Use firewall rules to restrict access to the HAProxy and `msgrpc` ports (e.g., 443 for HTTPS and 55553 for RPC) to trusted IP addresses only.
   - Consider implementing an IP-based access control list (ACL) on the HAProxy frontend to limit incoming traffic to known clients.

4. **Log Monitoring and Intrusion Detection**:
   - Configure syslog or `journalctl` to capture logs for both `msgrpc` and HAProxy services.
   - Regularly monitor logs for unusual activity or unauthorized access attempts. Integrate log monitoring with an intrusion detection system (IDS) if available.

5. **System Hardening**:
   - Keep the operating system and all software up-to-date with security patches.
   - Disable any unused services and remove unnecessary software to reduce the attack surface.
   - Use strong firewall rules to limit open ports and prevent unauthorized access.

6. **Session and Token Management**:
   - Implement session timeouts and rotate API tokens regularly to limit the exposure of stolen tokens.
   - Educate users on safeguarding tokens and avoid storing them in plain text.

7. **Regular Testing and Audits**:
   - Perform regular security testing, such as vulnerability scans and penetration tests, to identify potential weaknesses.
   - Audit system configurations and access permissions periodically to ensure compliance with security policies.
---

This introduction, objectives, and security requirements section provides a foundation for understanding the purpose, goals, and security considerations of setting up a high-availability and secure `msgrpc` environment. Let me know if you’d like further details on any section or additional topics included!


# Setting Up a High-Availability Metasploit RPC Server (`msgrpc`) Environment with HAProxy, SSL, and Keepalived on Ubuntu

This guide walks through the complete setup for creating a robust and highly available Metasploit RPC (`msgrpc`) server environment using HAProxy for load balancing, SSL for secure communication, and Keepalived for failover. It covers setting up `msgrpc` and HAProxy as services on Ubuntu, as well as testing and validating the configuration with `curl` commands.

---

## Objectives

1. **Automate Metasploit RPC (`msgrpc`) startup**: Run `msgrpc` as a root service that starts automatically on boot.
2. **Implement HAProxy**: Configure HAProxy for HTTPS, load balancing, and session persistence.
3. **Use Keepalived**: Set up high availability using a floating IP that fails over between two HAProxy instances.
4. **Secure and test the setup**: Use SSL certificates for secure communication and validate the setup with `curl`.
5. **Troubleshoot and optimize**: Add troubleshooting steps and optional configurations for additional resilience.

---

## Prerequisites

1. **Metasploit Installed**: Metasploit should be installed on the system.
2. **HAProxy Installed**: Install HAProxy on the load balancer server.
3. **Root Access**: Required to set up services, SSL, and Keepalived.
4. **SSL Certificate**: Self-signed or CA-signed certificate for HTTPS.
5. **At Least Two Backend Servers**: To run `msgrpc` for load balancing and failover.

---

![Qgo7yYP4T9rRhgAH9J9nEU](https://github.com/user-attachments/assets/bc7929eb-ac07-40c0-a28e-d84241832155)

## Step 1: Create a Systemd Service for Metasploit’s `msgrpc`

To make sure that `msgrpc` runs automatically on system boot, we’ll set it up as a `systemd` service. Running it as root ensures it has the necessary permissions for network operations and accessing system files.

### 1.1 Create the Systemd Service File

Start by creating a new `systemd` service file for `msgrpc`:

```bash
sudo nano /etc/systemd/system/msgrpc.service
```

### 1.2 Configure the Service File

Add the following configuration to the file, replacing any placeholders as needed. Here, `z80cpu` is used as an example password; make sure to replace it with a secure one.

```ini
[Unit]
Description=Metasploit RPC Server (msgrpc)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root  # Update to your Metasploit installation path if different
ExecStart=/usr/bin/msfconsole -q -x "load msgrpc Pass=z80cpu ServerHost=0.0.0.0 ServerPort=55553"
Restart=on-failure
TimeoutSec=300
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=msgrpc

[Install]
WantedBy=multi-user.target
```

#### Explanation of Configuration Parameters

- **User=root**: The service runs as the root user, necessary for `msgrpc` to operate with system-level permissions.
- **WorkingDirectory**: Specifies the directory where Metasploit is installed.
- **ExecStart**: The command to start `msfconsole` with `msgrpc`. The `-q` flag starts it in quiet mode, and `-x` executes the `msgrpc` command with specified options.
- **Restart=on-failure**: Automatically restarts the service if it crashes.
- **SyslogIdentifier=msgrpc**: Identifies the service’s logs in the syslog, useful for monitoring and troubleshooting.

### 1.3 Reload and Enable the Service

Reload `systemd` to apply the new service file, then enable it so it starts on boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable msgrpc.service
```

To start the service immediately, use:

```bash
sudo systemctl start msgrpc.service
```

You can verify the service status with:

```bash
sudo systemctl status msgrpc.service
```

### Security Considerations

- **Password Security**: Replace the password `z80cpu` with a more secure, randomly generated password.
- **Firewall Rules**: Configure the firewall to restrict access to the `msgrpc` port (55553 in this setup) to trusted sources only.
- **Monitoring**: Set up log monitoring using `syslog` or `journalctl` for the `msgrpc` service logs.

---

## Step 2: Configure HAProxy for HTTPS, Load Balancing, and Session Handling

With `msgrpc` running as a service, we’ll set up HAProxy to handle HTTPS connections, balance the load, and maintain session persistence across multiple backend servers.

### 2.1 Obtain or Create an SSL Certificate

An SSL certificate is required to set up HTTPS. You can obtain a certificate from a trusted Certificate Authority (CA) or create a self-signed certificate for testing:

```bash
sudo mkdir -p /etc/haproxy/certs
sudo openssl req -new -x509 -days 365 -nodes -out /etc/haproxy/certs/haproxy.pem -keyout /etc/haproxy/certs/haproxy.key
cat /etc/haproxy/certs/haproxy.key /etc/haproxy/certs/haproxy.pem > /etc/haproxy/certs/haproxy-ssl.pem
```

This command generates a certificate (`haproxy-ssl.pem`) that combines the private key and certificate.

### 2.2 Edit HAProxy Configuration for HTTPS and Load Balancing

Open the HAProxy configuration file, usually found at `/etc/haproxy/haproxy.cfg`:

```bash
sudo nano /etc/haproxy/haproxy.cfg
```

Replace the contents with the following configuration:

```plaintext
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 2000
    tune.ssl.default-dh-param 2048

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend rps_frontend
    bind *:443 ssl crt /etc/haproxy/certs/haproxy-ssl.pem
    mode tcp
    default_backend rps_backend

backend rps_backend
    mode tcp
    balance source
    hash-type consistent
    option httpchk GET /healthcheck
    timeout check 5s

    server rps1 <MFC_RPS_Server1_IP>:55553 check
    server rps2 <MFC_RPS_Server2_IP>:55553 check
```

### Explanation of Key Configurations

- **HTTPS Configuration**: Enables SSL on port 443, specifying the certificate file for encryption.
- **Session Persistence**: Uses source IP-based persistence to maintain user sessions with the same backend server.
- **Health Checks**: `option httpchk GET /healthcheck` monitors backend server health via an HTTP GET request.

### 2.3 Enable and Start HAProxy

Enable HAProxy to start on boot and start it immediately:

```bash
sudo systemctl enable haproxy
sudo systemctl start haproxy
```

Verify that HAProxy is running:

```bash
sudo systemctl status haproxy
```

---

## Step 3: Configure Keepalived for High Availability

Keepalived provides a floating IP that switches between two HAProxy servers, ensuring availability even if one HAProxy instance goes down.

### 3.1 Install Keepalived

Install Keepalived on both HAProxy servers:

```bash
sudo apt-get install keepalived
```

### 3.2 Configure Keepalived on the Primary Server

On the primary HAProxy server, edit the Keepalived configuration:

```bash
sudo nano /etc/keepalived/keepalived.conf
```

Add the following configuration, adjusting `interface`, `priority`, and `virtual_ipaddress`:

```plaintext
vrrp_instance VI_1 {
    state MASTER
    interface eth0  # Change this to your network interface
    virtual_router_id 51
    priority 101
    advert_int 1

    authentication {
        auth_type PASS
        auth_pass yourpassword
    }

    virtual_ipaddress {
        192.168.1.100/24  # This is the virtual IP
    }
}
```

### 3.3 Configure Keepalived on the Secondary Server

On the secondary server, use a similar configuration but set `state BACKUP` and use a lower `priority`, like 100.

### 3.4 Enable and Start Keepalived

Enable Keepalived on both servers:

```bash
sudo systemctl enable keepalived
sudo systemctl start keepalived
```

### Testing Failover

To test, stop HAProxy on the primary server and verify the secondary server takes over the VIP by running `ip addr show` to check for the VIP.

---

## Step 4: Testing the `msgrpc` Service with `curl`

Once `msgrpc` is running behind HAProxy, you can use `curl` commands to test the

 service and verify that it’s working correctly.

### 4.1 Authenticate to Obtain a Token

Authenticate to `msgrpc` to receive a token:

```bash
curl -X POST -H "Content-Type: application/json" \
-d '{"username": "msf", "password": "z80cpu"}' \
http://localhost:55553/api/v1/auth/login
```

You should receive a JSON response with an authentication token:

```json
{
    "token": "your_auth_token_here"
}
```

### 4.2 Test Other RPC Endpoints

Use the token to call additional endpoints. For example, to check the Metasploit version:

```bash
curl -X POST -H "Content-Type: application/json" \
-H "Authorization: Bearer your_auth_token_here" \
-d '{}' \
http://localhost:55553/api/v1/core/version
```

Replace `your_auth_token_here` with your token from the login response.

To list available exploits:

```bash
curl -X POST -H "Content-Type: application/json" \
-H "Authorization: Bearer your_auth_token_here" \
-d '{}' \
http://localhost:55553/api/v1/modules/exploits
```

### Troubleshooting Common Issues

- **Unauthorized Access**: If you receive a `401 Unauthorized` error, confirm that your token is correct and not expired.
- **SSL Errors**: If you encounter SSL errors, check that the correct certificate is specified and accessible by HAProxy.

---

## Conclusion

By completing this guide, you’ve successfully set up a high-availability Metasploit RPC server environment with HAProxy for load balancing and SSL for secure communication, enhanced by Keepalived for failover. Testing with `curl` confirms that `msgrpc` is accessible and working correctly.

With this setup, your Metasploit RPC server is resilient, secure, and capable of handling production-grade tasks. For further security, consider implementing IP whitelisting on the HAProxy frontend or additional firewall rules.
