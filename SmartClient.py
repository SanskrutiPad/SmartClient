import socket
import sys
import ssl
import re
import http.client
from typing import Dict


HTTPS_PORT_NUM = 443
HTTP_DEFAULT_PORT = 80


def main() -> None:

    """
    Main Function parses input and prints out required details from the decoded response received.

    Args: None

    Returns:
        type: None

    """

# Checks cmd line args and valid url
    big_cookie_dict = {}

    if len(sys.argv) < 2:
        print("Invalid input. Please refer to README.txt for input format.")
        sys.exit(0)
    else:
        user_input = sys.argv[1]
        prefix,domain = parse_uri(sys.argv[1])
        if prefix and domain:   
            uri = user_input if user_input.startswith("https://") else "https://"+user_input
            if not domain.startswith("www."):
                domain = "www." + domain
                uri = "https://" + domain
            print(user_input)
            print(f"URL:{uri}, Prefix: {prefix}, Domain: {domain}")
        else:
            print("Invalid URL. Please refer to README.txt for input format.")
            sys.exit(1)

    https_support = if_https_support(domain)
    socket_connect_resp(domain)
    http2_protocol = http2_support(domain)
    resp_data = socket_connect_resp(domain)

    # Decode captured response
    try:
        response_data = resp_data.decode('utf-8', errors='ignore')
    except:
        print("Error with decoding the captured response data from the server.")
    response_data = handle_redirects(response_data)  
    resp_data_type_header = get_content_type_headers(response_data)
    if (resp_data_type_header and "text/html" in resp_data_type_header):  
        response_data = response_data.decode("utf-8",errors="ignore")
    pass_protected = is_password_protected(response_data)
    http11_resp_data = http11_support(domain)
    big_cookie_dict = extract_cookies(resp_data)
    reformatted_cookies = "\n".join((f"Cookie: {key}: {value}" for key, value in big_cookie_dict.items()))
    print(response_data)
    
    
    # Final Output
    print("-----------------------FINAL OUTPUT-----------------------")
    print("Website: ",domain)
    print("Support of HTTP2 on web server:",http2_protocol)
    print("Support of HTTPS on web server:",https_support)
    if http11_resp_data:
        print("Support of HTTP1.1 on web server: True")
    else:
        print("Support of HTTP1.1 on web server: False")
    print("Password protected site?", pass_protected)
    if big_cookie_dict:
        print("\n\n-----------------------Cookies-----------------------")
        print(reformatted_cookies)
    else:
        print("No cookies detected.")





def handle_redirects(response_data)-> str:
    """
    This function handles redirects. It splits the response data attempting to find 301 and 302 status codes and find
    the new location from the redirect.

    Args:
        response_data (str): Response data captured from socket connection

    Returns:
        str: Redirected new_resp from redirected page or response_data otherwise
    """
    lines_resp_data = response_data.split('\r\n')
    if (lines_resp_data[0].startswith("HTTP/1.1 302") or lines_resp_data[0].startswith("HTTP/1.1 301")):
        for l in lines_resp_data:
            if l.startswith("Location:"):
                new_loc = l.split(' ')[1]

                new_resp = socket_connect_resp(new_loc.encode("utf-8",errors="ignore"))
                return handle_redirects(new_resp)
                
    return response_data        


    
def get_content_type_headers(resp_data)-> str:
    """
    Gets content type from headers in response data.

    Args:
        resp_data (str): Response data captured from socket connection

    Returns:
        str: Returns lines in response data, and an empty string otherwise
    """    
    lines_in_resp_data = resp_data.split("\r\n")
    for l in lines_in_resp_data:
        if l.startswith("Content-Type"):
            return lines_in_resp_data
        
    return ""    


def parse_uri(usr_input)->(str,str):
    """
    Parses user input from command line by matching with regex below.

    Args:
        usr_input (str): User input from command line.

    Returns:
        str, str: Returns url, and domain name
    """
    url_pattern = re.compile(r'(https://|www\.|)([a-zA-Z0-9.-]+)')
    match = url_pattern.match(usr_input)
    if match:
        prefix = match.group(1)
        domain = match.group(2)
        return prefix, domain
    else:
        return None, None




def extract_cookies(decoded_web_data)->Dict[str,str]:
    """
    Finds cookies from response data.

    Args:
        decoded_web_data (str): Decoded response data from web server

    Returns:
        Dict[str, str]: Dictionary of cookies found from response data
    """
    decoded_data_str = decoded_web_data.decode("utf-8",errors="ignore")
    headers, body = decoded_data_str.split('\r\n\r\n',1)
    head_lines = headers.split("\r\n")
    cookie_jar = {}

    for line in head_lines:
        if line.startswith("Set-Cookie"):
            print("Found a cookie!!")
            cookie_information = line.split(':',1)[1].strip()
            cookie_pairs = cookie_information.split(';')

            for pair_cookies in cookie_pairs:
                pair_cookies = pair_cookies.strip()
                if "=" in pair_cookies:
                    key,value = pair_cookies.split("=",1)
                cookie_jar[key] = value


    return cookie_jar  






def if_https_support(usr_input) -> bool:
    """
    Finds if web server supports 'https://'

    Args:
        usr_input (str): User input from command line.

    Returns:
        bool: Returns True if web supports https://, returns False otherwise
    """
    if "https://" in usr_input:
        return True
    else:
        return False





def socket_connect_resp(web_server:str)->str:
    """
    This method connects the web server to an SSL Socket.

    Args:
        web_server (str): Domain of web page.

    Returns:
        str: Response from socket connection

    Raises:
        socket.error: Socket Creation Error
        socket.error: Socket Wrapping error
        socket.error: Socket Connection Error
        socket.error: Socket send request error
        socket.timeout: If default time runs out on socket
        soc.error: Closing socket Error
    """

    socket.setdefaulttimeout(5)

    # Creates socket
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print(f"Error creating the socket: {e}")
        sys.exit(0)

    # Enables SSL
    ssl_prep = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    
  
    # Wrap socket
    try:
        socket_ssl = ssl_prep.wrap_socket(client_sock,server_hostname=web_server)
    except:
        print("Error in wrapping client_sock inside https_support(web_server: str)")

    # Attempts socket connection
    try:
        socket_ssl.connect((web_server,HTTPS_PORT_NUM))
        print(f"Connection to {web_server} on port {HTTPS_PORT_NUM} successful!")
    except socket.error as err: 
        print(f"Connection to host failed with error {err}\Exiting...")
        sys.exit(0)

    # # sends an HTTP GET request
    request_path = f"GET / HTTP/1.1\r\nHost: {web_server} \r\nConnection:Keep-Alive\r\n\r\n"

    print("\n\n-----------------REQUEST DATA-----------------")
    print(request_path)
    try:
        socket_ssl.send(request_path.encode())

    except socket.error as error2:
        print(f"Error sending GET Request: {error2}\nExiting...")
        sys.exit(0)

    print("\n\n-----------------RESPONSE DATA-----------------")
    

    # response data
    try:
        data_recv = socket_ssl.recv(10000)
    except socket.timeout:
        ("Socket receive op timed out:(")
    except socket.error as error3:
        print(f"Error receiving HTTPS response: {error3}\nExiting...")
        sys.exit(0)


    finally:    
        try:
            socket_ssl.close()
        except socket_ssl.error as err_s_close:
            print(f"Error while closing socket inside https_support(web_server:str)->str: {err_s_close}")
            sys.exit(0)

    return data_recv







def http11_support(web_server)->str:
    """
    This finds out if the web page supports HTTP1.1 Protocol. This was created prior to the updated assignment rubric.

    Args:
        web_server (str): Domain of web page.

    Returns:
        str: Response from socket connection

    Raises:
        socket.error: Socket Creation Error
        socket.error: Socket Connection Error
        socket.error: Socket send request error
        socket.timeout: If default time runs out on socket
        socket.error: Error receiving response
        soc.error: Closing socket Error
    """
    socket.setdefaulttimeout(5)
    try:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err_create:
        print(f"Error in socket creation inside http11_support(usr_input)->str: {err_create}")
        sys.exit(0)

    # Connect socket w/TCP Connection
    try:
        soc.connect((web_server, HTTP_DEFAULT_PORT))
    except socket.error as err_connect:
        print(f"Error in socket connection inside http11_support(usr_input)->str: {err_connect}")
        sys.exit(0)
    request_path2 = f"GET / HTTP/1.1\r\nHost: {web_server} \r\nConnection:Keep-Alive\r\n\r\n"

    # Send Request
    print("\n\n-----------------REQUEST DATA HTTP1.1-----------------")
    try:
        soc.send((request_path2.encode('utf-8', errors='ignore')))
    except socket.error as soc_get_err:
        print(f"Error in socket request inside http11_support(usr_input)->str: {soc_get_err}")
        sys.exit(0)

    print("\n\n-----------------RESPONSE DATA-----------------")
    # response data
    try:
        resp2 = b""     # empty container to fill response data
        while(True):
            data_recv = soc.recv(1024)
            if not data_recv:
                break
            # data_recv = data_recv.decode(errors="ignore")
            resp2 += data_recv
    except socket.timeout:
        ("Socket receive op timed out:( in http11_support(usr_input)->str:")
    except socket.error as error3:
        print(f"Error receiving HTTPS response: {error3}\nExiting...")
        sys.exit(0)


    finally:    
        try:
            soc.close()
        except soc.error as err_s_close:
            print(f"Error while closing socket inside https_support(web_server:str)->str: {err_s_close}")
            sys.exit(0)
    return resp2






def http2_support(url: str)-> bool:
    """
    This method finds if the web page supports HTTP2 Protocol.

    Args:
        url (str): URL of web page.

    Returns:
        socket.error: socket creation
        socket.error: Sees if wrapped socket contains error with app layer handshake

    Raises:
        ExceptionType: Description of when this exception is raised.
    """
    # Enable SSL
    ssl_prep1 = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    ssl_prep1.set_alpn_protocols(["h2", "HTTP/1.1"])

    # Create socket
    try:
        ssl_soc1 = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    except socket.error as err:
        print(f"Error with socket creation in http2_support(url: str)-> bool: {err}")

    # Attempt to connect
    try:
        ssl_soc1.connect((url,HTTPS_PORT_NUM))
    except:
        print("Error with connecting to Host in http2_support(url: str)-> bool")

    # Wrap socket
    try:
        ssl_sco1_wrapped = ssl_prep1.wrap_socket(ssl_soc1,server_hostname=url)
    except:
        print("Error with wrapping socket in http2_support(url: str)-> bool")

    try:
        app_layer_protocol = ssl_sco1_wrapped.selected_alpn_protocol()
    except socket.error as err1:
        print(f"Error with application layer protocol handshake: {err1}")
    
    if app_layer_protocol:
        return True
    else:
        return False




def is_password_protected(uri) -> bool:
    """
    This function attempts to find out if the web page is password protected.

    Args:
        uri (str): uri of web page

    Returns:
        bool: True if the web page is password protected, False otherwise

    Raises:
        http.client.ResponseNotReady: If response object is not ready to be processed
        Exception: General Exception Error
    """

    try:
        prefix,place_holder = parse_uri(uri)
        if not prefix:
            uri = "https://" + uri
        # while(True):    
            connection = http.client.HTTPSConnection(uri,HTTPS_PORT_NUM)
            connection.request("GET", "/")

            try:    
                resp = connection.getresponse()
            except http.client.ResponseNotReady as pass_prot_resp_err:
                print(f"Error in is_password_protected(uri)->bool; ResponseNotReady Error detected: {pass_prot_resp_err}")

            if (resp.status == 302 or resp.status == 301):
                header_loc = resp.getheader("Location")

                if (header_loc):
                    uri = header_loc
                else:
                    return False
            # else:
                # break


        if (resp.status == 401):
            return True
        else:
            return False
    
    except Exception as e:
        print(f"Some Exception Error occurred in is_password_protected(uri) -> bool: {e}")


if __name__ == "__main__":
    main()
