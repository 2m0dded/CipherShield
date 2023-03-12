
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <QApplication>
#include <QSystemTrayIcon>
#include <QMenu>

const std::string kHostname = "www.example.com";
const std::string kServername = kHostname + ":443";
const std::string kRequest = "GET / HTTP/1.1\r\nHost: " + kHostname + "\r\n\r\n";
const size_t kResponseSize = 1024;

void HandleSSLError(const std::string& message, SSL* ssl) {
  std::cerr << message << std::endl;
  ERR_print_errors_fp(stderr);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  exit(EXIT_FAILURE);
}

void HandleBIOError(const std::string& message, BIO* bio) {
  std::cerr << message << std::endl;
  BIO_free_all(bio);
  exit(EXIT_FAILURE);
}

void Cleanup(SSL_CTX* ctx, SSL* ssl, BIO* bio) {
  SSL_shutdown(ssl);
  SSL_free(ssl);
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
}

int main(int argc, char* argv[]) {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_client_method());
  SSL* ssl = SSL_new(ctx);
  SSL_set_tlsext_host_name(ssl, kHostname.c_str());

  BIO* bio = BIO_new_ssl_connect(ctx);
  BIO_set_conn_hostname(bio, kServername.c_str());
  BIO_get_ssl(bio, &ssl);
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  if (BIO_do_connect(bio) <= 0) {
    HandleBIOError("Failed to connect to server", bio);
  }

  if (BIO_do_handshake(bio) <= 0) {
    HandleBIOError("TLS handshake failed", bio);
  }

  X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), kHostname.c_str(), 0);
  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    HandleSSLError("Certificate verification error", ssl);
  }

  if (SSL_write(ssl, kRequest.c_str(), kRequest.length()) <= 0) {
    HandleSSLError("Failed to send HTTP request", ssl);
  }

  char response[kResponseSize];
  int response_length = SSL_read(ssl, response, kResponseSize - 1);
  if (response_length <= 0) {
    HandleSSLError("Failed to receive HTTP response", ssl);
  }

  response[response_length] = '\0';
  std::cout << "Encrypted response: " << response << std::endl;

  Cleanup(ctx, ssl, bio);

  QApplication app(argc, argv);
  QSystemTrayIcon trayIcon(QIcon(":/images/icon.png"), nullptr);
  trayIcon.setToolTip("My App");
  QMenu* menu = new QMenu();
  trayIcon.setContextMenu(menu);
  trayIcon.show();

  return app.exec();
}
