#pragma once

#ifndef BCLIB_HPP_
#define BCLIB_HPP_

#ifndef ASIO_STANDALONE
  #define ASIO_STANDALONE
#endif

#include <asio.hpp>

#define BCLIB_VERSION "1.0.0"

#define LOG(x) log(std::string("[BCLib] ") + x)

#include "server_ws.hpp"
using WsServer = SimpleWeb::SocketServer<SimpleWeb::WS>;

#include "nlohmann/json.hpp"
#include "sio_client.h"

#include <windows.h>
#include <shellapi.h>
#include <Shlobj_core.h>
#include <ctime>
#include <iostream>
#include <sstream>
#include <vector>
#include <thread>

using json = nlohmann::json;

struct BCLib {
	BCLib(const char* game, const char* name, std::function<void(std::string)> log) : name(name),
		game(game),
		log(log),
		loggedIn(std::make_shared<bool>(false)),
		cur_server(std::make_shared<std::string>("")) 
	{
		server.config.port = 8477;
		LOG("Initialized!");
	}

	BCLib(const char* game, const char* name) : BCLib(game, name, [](std::string) {}) {}
	BCLib(const char* game) : BCLib(game, std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()).c_str()) {}
	BCLib() : BCLib("") {}

	// Websocket server used by the Control Board for one-click login. Thread-blocking.
	void StartCBServer() {
		using namespace std::placeholders;
		using namespace std;

		LOG("Starting WebSocket server");
		auto& ep = server.endpoint["^/bclib/?$"];

		ep.on_message = [&](shared_ptr<WsServer::Connection> connection, shared_ptr<WsServer::InMessage> in_message) {
			auto out_message = in_message->string();

			cout << "Server: Message received: \"" << out_message << "\" from " << connection.get() << endl;

			if (out_message == "stop") {
				LOG("Closing from websocket.");

				// connection->send is an asynchronous function
				connection->send("STOPPING", [&](const SimpleWeb::error_code& ec) {
					if (ec) {
						LOG("Server: Error sending stopping message. " +
							// See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
							"Error: " + to_string(ec.value()) + ", error message: " + ec.message());
					}
					Stop();
					});
			}
			else if (out_message.find("connect", 0) == 0) {
				std::vector<std::string> args = split(out_message, " ");
				if (args.size() >= 2) {
					Disconnect();
					Connect(args[1], args.size() >= 3 ? args[2] : "");
					connection->send("CONNECT " + args[1], [&](const SimpleWeb::error_code& ec) {});
				}
				else {
					connection->send("CONNECT_ERROR NOT_ENOUGH_ARGS", [&](const SimpleWeb::error_code& ec) {});
				}
			}
		};

		ep.on_open = [&](shared_ptr<WsServer::Connection> connection) {
			LOG("Server: Opened connection " + connection->remote_endpoint().address().to_string() + ":" + to_string(connection->remote_endpoint().port()));
			connection->send("{\"name\":\"" + std::string(name) + "\",\"game\":\"" + game + "\"}", [&](const SimpleWeb::error_code& ec) {});
		};

		// See RFC 6455 7.4.1. for status codes
		ep.on_close = [&](shared_ptr<WsServer::Connection> connection, int status, const string& /*reason*/) {
			LOG("Server: Closed connection " + connection->remote_endpoint().address().to_string() + ":" + to_string(connection->remote_endpoint().port()) + "with status code " + to_string(status));
		};

		// Can modify handshake response headers here if needed
		ep.on_handshake = [&](shared_ptr<WsServer::Connection> /*connection*/, SimpleWeb::CaseInsensitiveMultimap& /*response_header*/) {
			return SimpleWeb::StatusCode::information_switching_protocols; // Upgrade to websocket
		};

		// See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
		ep.on_error = [&](shared_ptr<WsServer::Connection> connection, const SimpleWeb::error_code& ec) {
			LOG("Server: Error in connection " + connection->remote_endpoint().address().to_string() + ":" + to_string(connection->remote_endpoint().port()) + ". Error: " + to_string(ec.value()) + ", error message: " + ec.message());
		};

		server.start([&](unsigned short port) {
			LOG("Server listening on port " + to_string(port));
		});
	}

	// Stops the websocket server.
	void StopCBServer() {
		LOG("Stopping server");
		server.stop();
	}

	// Connects to the specified server with a blank token. This will open a login webpage if the server is online.
	void Connect(const std::string& server) { 
		Connect(server, "");
	};

	// Connects to the specified server with a given token. This will bypass webpage login.
	void Connect(const std::string& serv, const std::string& token) {
		client.clear_con_listeners();
		client.clear_socket_listeners();
		client.set_reconnect_delay(1000);
		client.set_reconnect_delay_max(5000);
		client.set_reconnect_attempts(2);
		client.set_reconnecting_listener([&, serv]() {
			LOG("Attempting to reconnect to '" + serv + "'...");
			*loggedIn = false;
		});
		client.set_fail_listener([&]() {
			LOG("Socket failed.");
			*loggedIn = false;
		});
		client.set_open_listener([&, serv, token]() {
			*loggedIn = false;
			LOG("Socket connected");

			// If a token was passed into connect, use it to directly log in. Otherwise display website.
			if (token.size() == 0) {
				client.socket()->emit("login", sio::message::list("PLUGIN"), [&, serv](const sio::message::list& list) {
					std::string res = list[0]->get_string();
					std::string site = serv + res;
					LOG("RESPONSE: " + res);
					LOG("Total: " + site);

					// Open default browser
					ShellExecuteA(0, 0, site.c_str(), 0, 0, SW_SHOW);
					});
			}
			else {
				sio::message::list args = sio::message::list(token);
				args.push("PLUGIN");
				args.push(std::string(name));
				client.socket()->emit("login:token", args);
			}

			client.socket()->on("logged_in", [&](const std::string& name, sio::message::ptr const& message, bool need_ack, sio::message::list& ack_message) {
				*loggedIn = true;
				client.set_reconnect_attempts(3600);
			});
		});
		client.set_close_listener([&](int const& reason) {
			*loggedIn = false;
			LOG("Socket closed");
		});
		*cur_server = serv;
		LOG("Attempting to connect to '" + serv + "'...");
		client.connect(serv);
	}

	// Disconnects from the current server.
	void Disconnect() {
		if (client.opened()) {
			LOG("Disconnecting from server.");
			client.socket()->off_all();
			client.clear_con_listeners();
			client.clear_socket_listeners();
			client.set_reconnect_attempts(0);
			client.set_reconnect_delay(0);
			clock_t time_req = clock();
			client.sync_close();
			time_req = clock() - time_req;
			LOG("Disconnected. (" + std::to_string(((float)time_req / CLOCKS_PER_SEC)) + "s)");
		} else {
			LOG("Client already disconnected.");
		}
	}

	// Destroys the websocket server and client.
	void Stop() {
		StopCBServer();
		Disconnect();
	}

	// Sends the event to the relay for parsing and distribution to the overlays.
	void SendEvent(std::string eventName, const json& jsawn) {
		json event;
		event["game"] = game;
		event["event"] = eventName;
		event["data"] = jsawn;

		if (client.opened()) {
			client.socket()->emit("game event", event.dump());
		}
	}

	bool Connected() {
		return client.opened();
	}

	const char* game;
	const char* name;
	sio::client client;
	std::shared_ptr<bool> loggedIn;
	std::shared_ptr<std::string> cur_server;
	std::function<void(std::string)> log;

	WsServer server;

	std::vector<std::string> split(std::string s, std::string delimiter) {
		size_t pos_start = 0, pos_end, delim_len = delimiter.length();
		std::string token;
		std::vector<std::string> res;

		while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
			token = s.substr(pos_start, pos_end - pos_start);
			pos_start = pos_end + delim_len;
			res.push_back(token);
		}

		res.push_back(s.substr(pos_start));
		return res;
	}
};
#endif // BCLIB_HPP_