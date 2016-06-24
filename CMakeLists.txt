CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
PROJECT(h2)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

SET(CMAKE_VERBOSE_MAKEFILE ON)

FIND_PACKAGE(Threads REQUIRED)
FIND_PACKAGE(OpenSSL REQUIRED)
IF (OPENSSL_VERSION VERSION_LESS "1.0.2")
    MESSAGE(WARNING "*********************************************************************** OpenSSL 1.0.2 is required for HTTP/2 interoperability with web browsers ***********************************************************************")
ENDIF (OPENSSL_VERSION VERSION_LESS "1.0.2")

FIND_PACKAGE(ZLIB REQUIRED)
FIND_PACKAGE(LibUV)

INCLUDE_DIRECTORIES(include ${ZLIB_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${LIBUV_INCLUDE_DIR} "${CMAKE_SOURCE_DIR}/h2" "${CMAKE_SOURCE_DIR}/wslay")


IF (MSVC)
	ADD_COMPILE_OPTIONS("-D_CRT_SECURE_NO_WARNINGS")
ENDIF(MSVC)
IF(NOT MSVC)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
ENDIF(NOT MSVC)


SET(H2_SOURCE_FILES
		"h2/cache.c"
		"h2/casper.c"
		"h2/chunked.c"
		"h2/compress.c"
		"h2/config.c"
		"h2/configurator.c"
		"h2/connection.c"
		"h2/context.c"
		"h2/errordoc.c"
		"h2/events.c"
		"h2/expires.c"
		"h2/fastcgi.c"
		"h2/file.c"
		"h2/filecache.c"
		"h2/frame.c"
		"h2/gzip.c"
		"h2/headers.c"
		"h2/hostinfo.c"
		"h2/hpack.c"
		"h2/http1.c"
		"h2/http1client.c"
		"h2/logconf.c"
		"h2/memory.c"
		"h2/mimemap.c"
		"h2/multithread.c"
		"h2/picohttpparser.c"
		"h2/proxy.c"
		"h2/redirect.c"
		"h2/reproxy.c"
		"h2/request.c"
		"h2/requests.c"
		"h2/scheduler.c"
		"h2/serverutil.c"
		"h2/socket.c"
		"h2/socketpool.c"
		"h2/status.c"
		"h2/stream.c"
		"h2/string.c"
		"h2/throttle_resp.c"
		"h2/time.c"
		"h2/timeout.c"
		"h2/token.c"
		"h2/tunnel.c"
		"h2/url.c"
		"h2/util.c"
		"h2/websocket.c")

SET(WSLAY_SOURCE_FILES
		"wslay/wslay_event.c"
		"wslay/wslay_frame.c"
		"wslay/wslay_net.c"
		"wslay/wslay_queue.c"
		"wslay/wslay_stack.c")

ADD_LIBRARY(h2 ${H2_SOURCE_FILES})

ADD_LIBRARY(wslay ${WSLAY_SOURCE_FILES})

ADD_EXECUTABLE(test "test/main.cpp")
TARGET_LINK_LIBRARIES(test h2 wslay ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARY_DIRS} ${LIBUV_LIBRARIES})