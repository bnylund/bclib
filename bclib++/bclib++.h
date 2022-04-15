#pragma once

#ifndef ASIO_STANDALONE
  #define ASIO_STANDALONE
#endif

#define WIN32_LEAN_AND_MEAN
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

using json = nlohmann::json;

class BCLib {
public:
	BCLib(const char* game, const char* name, std::function<void(std::string)> log);
	BCLib(const char* game, const char* name) : BCLib(game, name, [](std::string) {}) {}
	BCLib(const char* game) : BCLib(game, std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()).c_str()) {}
	BCLib() : BCLib("") {}

	// Websocket server used by the Control Board for one-click login. Thread-blocking.
	void StartCBServer();

	// Stops the websocket server.
	void StopCBServer();

	// Connects to the specified server with a blank token. This will open a login webpage if the server is online.
	void Connect(std::string server) { Connect(server, ""); };

	// Connects to the specified server with a given token. This will bypass webpage login.
	void Connect(std::string server, std::string token);

	// Disconnects from the current server.
	void Disconnect();

	// Destroys the websocket server and client.
	void Stop();

	// Sends the event to the relay for parsing and distribution to the overlays.
	void SendEvent(std::string eventName, const json& jsawn);

	const char* game;
	const char* name;
	sio::client h;
	std::shared_ptr<bool> loggedIn;
	std::shared_ptr<std::string> cur_server;
private:
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