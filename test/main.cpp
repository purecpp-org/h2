
#include <iostream>
#include <string>
#include <vector>

extern "C"
{
#include <h2o.h>
#include <h2o/http1.h>
//#include <h2o/socket/evloop.h>
#include <h2o/socket/uv-binding.h>
//#include <h2o/http2.h>
#include <h2o/websocket.h>
#include <wslay/wslay.h>
}

// h2o_globalconf_t config;
// h2o_context_t ctx;
// // SSL_CTX *ssl_ctx = NULL;
// h2o_accept_ctx_t accept_ctx;


h2o_globalconf_t config;

struct thread_data_t
{
	h2o_context_t ctx;
	// SSL_CTX *ssl_ctx = NULL;
	h2o_accept_ctx_t accept_ctx;
	uv_thread_t tid;
};

std::vector<thread_data_t> thread_data;

static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int(*on_req)(h2o_handler_t *, h2o_req_t *))
{
	h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
	h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
	handler->on_req = on_req;
	return pathconf;
}

static int post_test(h2o_handler_t *self, h2o_req_t *req)
{
	if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")) &&
		h2o_memis(req->path_normalized.base, req->path_normalized.len, H2O_STRLIT("/post-test/"))) {
		static h2o_generator_t generator = { NULL, NULL };
		req->res.status = 200;
		req->res.reason = "OK";
		h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
		h2o_start_response(req, &generator);
		h2o_send(req, &req->entity, 1, 1);
		return 0;
	}

	return -1;
}

static void on_ws_message(h2o_websocket_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg)
{
	if (arg == NULL) {
		h2o_websocket_close(conn);
		return;
	}

	if (!wslay_is_ctrl_frame(arg->opcode)) {
		struct wslay_event_msg msgarg = { arg->opcode, arg->msg, arg->msg_length };
		wslay_event_queue_msg(conn->ws_ctx, &msgarg);
	}
}

static int websocket(h2o_handler_t *self, h2o_req_t *req)
{
	const char *client_key;

	if (h2o_is_websocket_handshake(req, &client_key) != 0 || client_key == NULL) {
		return -1;
	}
	h2o_upgrade_to_websocket(req, client_key, NULL, on_ws_message);
	return 0;

}

static int index(h2o_handler_t *self, h2o_req_t *req)
{
	std::cout << uv_thread_self() << std::endl;
	if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET"))) {
		static h2o_generator_t generator = { NULL, NULL };
		req->res.status = 200;
		req->res.reason = "OK";
		//h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
		h2o_start_response(req, &generator);
		h2o_iovec_t body = h2o_strdup(&req->pool, "Test", sizeof("Test") - 1);
		h2o_send(req, &body, 1, 1);
		return 0;
	}

	return -1;
}

static int chunked_test(h2o_handler_t *self, h2o_req_t *req)
{
	static h2o_generator_t generator = { NULL, NULL };

	if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
		return -1;

	h2o_iovec_t body = h2o_strdup(&req->pool, "hello world\n", sizeof("hello world\n")-1);
	req->res.status = 200;
	req->res.reason = "OK";
	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
	h2o_start_response(req, &generator);
	h2o_send(req, &body, 1, 1);

	return 0;
}

static void echo_alloc(uv_handle_t* handle,
	size_t suggested_size,
	uv_buf_t* buf) {
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
}

static void after_read(uv_stream_t* handle,
	ssize_t nread,
	const uv_buf_t* buf) {
	std::cout << std::string(buf->base, nread) << std::endl;
}

static void on_accept(uv_stream_t *listener, int status)
{
	if (status != 0)
		return;
	static int i = 0;
	++i;
	if (i == 24)
	{
		i = 0;
	}

	uv_tcp_t *conn = (uv_tcp_t*)h2o_mem_alloc(sizeof(*conn));
	uv_tcp_init(thread_data[i].ctx.loop, conn);

	if (uv_accept(listener, (uv_stream_t *)conn) != 0) {
		uv_close((uv_handle_t *)conn, (uv_close_cb)free);
		return;
	}

//  	uv_read_start((uv_stream_t*)conn, echo_alloc, after_read);

	h2o_socket_t *sock = h2o_uv_socket_create((uv_stream_t *)conn, (uv_close_cb)free);
	h2o_accept(&thread_data[i].accept_ctx, sock);
}

static int create_listener()
{
	struct sockaddr_in addr;
	int r;

	static uv_tcp_t listener;

	uv_tcp_init(thread_data[0].ctx.loop, &listener);
	uv_ip4_addr("0.0.0.0", 7891, &addr);
	if ((r = uv_tcp_bind(&listener, (struct sockaddr *)&addr, 0)) != 0)
	{
		fprintf(stderr, "uv_tcp_bind:%s\n", uv_strerror(r));
		goto Error;
	}
	listener.data = (void*)index;
	if ((r = uv_listen((uv_stream_t *)&listener, 128, on_accept)) != 0)
	{
		fprintf(stderr, "uv_listen:%s\n", uv_strerror(r));
		goto Error;
	}

	return 0;
Error:
	uv_close((uv_handle_t *)&listener, NULL);
	return r;
}

static int reproxy_test(h2o_handler_t *self, h2o_req_t *req)
{
	if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
		return -1;

	req->res.status = 200;
	req->res.reason = "OK";
	h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_X_REPROXY_URL, H2O_STRLIT("http://www.ietf.org/"));
	h2o_send_inline(req, H2O_STRLIT("you should never see this!\n"));

	return 0;
}

static int setup_ssl(const char *cert_file, const char *key_file, size_t index)
{
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	auto& accept_ctx = thread_data[index].accept_ctx;
		accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_options(accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);

// 	if (USE_MEMCACHED) {
// 		accept_ctx.libmemcached_receiver = &libmemcached_receiver;
// 		h2o_accept_setup_async_ssl_resumption(h2o_memcached_create_context("127.0.0.1", 11211, 0, 1, "h2o:ssl-resumption:"), 86400);
// 		h2o_socket_ssl_async_resumption_setup_ctx(accept_ctx.ssl_ctx);
// 	}

	/* load certificate and private key */
	if (SSL_CTX_use_certificate_file(accept_ctx.ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
		return -1;
	}

	/* setup protocol negotiation methods */
#if H2O_USE_NPN
	h2o_ssl_register_npn_protocols(accept_ctx.ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
	h2o_ssl_register_alpn_protocols(accept_ctx.ssl_ctx, h2o_http2_alpn_protocols);
#endif

	return 0;
}

void run_loop(void* index)
{
	uv_run(thread_data[(size_t)index].ctx.loop, UV_RUN_DEFAULT);
}

int main()
{
	h2o_config_init(&config);

	h2o_hostconf_t *hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);
	register_handler(hostconf, "/post-test", post_test);
	register_handler(hostconf, "/chunked-test", chunked_test);
	h2o_reproxy_register(register_handler(hostconf, "/reproxy-test", reproxy_test));
	h2o_file_register(h2o_config_register_path(hostconf, "/static", 0), "static", NULL, NULL, H2O_FILE_FLAG_DIR_LISTING);
	register_handler(hostconf, "/websocket", websocket);
	register_handler(hostconf, "/", index);
	config.server_name.len = 0;

	thread_data.resize(24);
	for (size_t i = 0; i < 24; ++i)
	{
		thread_data_t& data = thread_data[i];
		uv_loop_t loop;
		uv_loop_init(&loop);
		h2o_context_init(&data.ctx, &loop, &config);

	// 	if (setup_ssl("cert/server.crt", "cert/server.key") != 0)
	// 	{
	// 		fprintf(stderr, "failed to setup ssl\n");
	// 		return 1;
	// 	}

		data.accept_ctx.ctx = &data.ctx;
		data.accept_ctx.hosts = config.hosts;


		uv_thread_create(&data.tid, &run_loop, (void*)i);
	}

	if (create_listener() != 0)
	{
		fprintf(stderr, "failed to listen to 127.0.0.1:7891:%s\n", strerror(errno));
		return 1;
	}
	for (auto& data : thread_data)
	{
		uv_thread_join(&data.tid);
	}

	return 0;
}