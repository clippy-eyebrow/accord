#pragma once

// OPENSSL IS REQUIRED!
// There's really no way around this because discord rightfully uses https everywhere, and you can't escape OpenSSL if you're doing anything with SSL.
// soooo this will still be a single header library... with one dependency that is widely supported and cross-platform.
// here's an all-in-one solution for windows that includes headers/libs/dlls, all you need to link with OpenSSL.
// https://kb.firedaemon.com/support/solutions/articles/4000121705

#define CPPHTTPLIB_OPENSSL_SUPPORT

// EXTREMELY BASED
// please support the author of this lib! https://github.com/dhbaird/easywsclient
#include "easywsclient.h"
#include "httplib.h"
#include "ajson.h"

// >msvc thought this was a good idea
#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
#endif

/*

can we make a simple discord library in C++? duh

this can be as simple as discord.xx without dicking around with python or javascript! Here!
And all that in a single-header format to avoid dicking around with C++'s cmake/makefile/blahblahblah
Productivity over all else and so on and so forth

*/

/**
 * UTILS
 */

#define cast_u8 static_cast<uint8_t>
#define cast_u16 static_cast<uint16_t>
#define cast_u64 static_cast<uint64_t>
#define bind_this(member, type, arg) [this](type arg){member(arg);} // this looks only a little less ridiculous

const char* GetOSName() {
#ifdef _WIN32
    return "windows";
#elif _WIN64
    return "windows";
#elif __APPLE__ || __MACH__
    return "macos";
#elif __linux__
    return "linux";
#else
    return "other";
#endif
}

#ifdef NDEBUG
    #define DEBUG_LOG(...)
#else
    #define DEBUG_LOG printf
#endif

/**
 * CONSTANTS
 */

// yeah yeah yeah yeah yeah yeah yeah yeah yeah
static const char* ACCORD_LIB_NAME = "accord";

// Discord likes changing this, no need for fancy interpolation bud
#define DISCORD_V6

#if defined(DISCORD_V6)

// base addresses
static const char* D_API_BASE = "https://discord.com/api/v6";
static const char* D_HOSTNAME = "discord.com";
static const char* D_GATEWAY_BASE = "wss://gateway.discord.gg";

// routes
static const char* D_GATEWAY_CHECK = "/api/v6/gateway";
static const char* D_GATEWAY_BOT_CHECK = "/api/v6/gateway/bot";

#endif

static const char* D_HEADER_BOT_AUTH = "Bot ";
static const char* D_HEADER_BEARER_AUTH = "Bearer ";

/**
 * ENUMS
 */

enum class DMsgType : uint8_t {
    USER = 0,
    NICK,
    CHANNEL,
    ROLE,
    EMOJI,
    ANIM_EMOJI,
    MAX
};

enum class DOpcode : int {
    HEARTBEAT = 1,
    IDENT = 2,
    HELLO = 10
};

enum class DEventType : uint8_t {
    SEND_IDENT = 0,
    SEND_HEARTBEAT
};

/**
 * STRUCTURES
 */

 // structure to parse and store discord's ID system
struct DSnowflake {
    // unix epoch might be useful
    static const uint64_t DiscordEpoch = 1420070400000;

    uint64_t Timestamp; // considered from the first second of 2015
    uint8_t InternalWID; // workerID
    uint8_t InternalPID; // processID
    uint16_t Increment; // relative ID generated from the processID

    DSnowflake(uint64_t Snowflake) {
        Timestamp   = cast_u64((Snowflake & 0x000000) >> 22);
        InternalWID = cast_u8 ((Snowflake & 0x3E0000) >> 17);
        InternalPID = cast_u8 ((Snowflake & 0x01F000) >> 12);
        Increment   = cast_u16((Snowflake & 0x000FFF) >> 00);
    }

    // time helpers
    uint64_t ToUnixTime() { return Timestamp + DiscordEpoch; }
    uint64_t RawTime() { return Timestamp; }
};

// internal event system that reacts to events from the websocket connection
template<typename ...Args>
struct DEvent {
    DEventType Type;
    std::function<void(Args...)> Func;
};

// allow the user to pass in some args to be bound to the event functions
template<typename ...Args>
class DEventSystem {
    // this holds the queue of actual events
    std::queue<DEventType> EventQueue;

    // this has the mapping of defined events from anywhere, keeping defines in one place allows the system to push an event by type rather than by function
    std::unordered_map<DEventType, DEvent<Args...>> EventMap;

    // Store whatever gets passed in
    std::tuple<Args...> BoundArgs;

    // this is what .pop() should do... STL is a mess
    template<typename T>
    T Pop(std::queue<T>& Q) {
        T data = Q.back();
        Q.pop();
        return data;
    }

    // template haxoring, the idea here is we want to take the tuple storing our arguments and unpack them into the function we want to call
    template<std::size_t... I>
    void call_func_impl(std::function<void(Args...)>& Callee, std::tuple<Args...> Tuple, std::index_sequence<I...>) {
        Callee(std::get<I>(Tuple)...);
    }

    void call_func(std::function<void(Args...)>& Callee, std::tuple<Args...> Tuple) {
        call_func_impl(Callee, Tuple, std::make_index_sequence<std::tuple_size_v<std::tuple<Args...>>>{});
    }

public:
    DEventSystem(Args... Bruh) : BoundArgs(std::make_tuple(Bruh...)) {}

    // process a queued event every tick? Sure that's good enough for now
    void Update() {
        if (EventQueue.size()) {
            call_func(EventMap[Pop(EventQueue)].Func, BoundArgs);
        }
    }

    void AddEvent(DEventType Type, std::function<void(Args...)> Func) {
        EventMap[Type] = { Type, Func }; // I dont care if a type gets overwritten
    }

    void QueueEvent(DEventType Type) {
        EventQueue.push(Type);
    }
};

/**
 * JSON INTERFACES
 * ajson uses an ORM-type system which parses buffers into structs
 * Res is a response - recieving info from the server
 * Req is a request - sending info to the server
 */

// At the bare minimum we have an opcode
struct DGatewayPayloadBase {
    int op;
};
AJSON(DGatewayPayloadBase, op);

// Discord says to expect the data to be "anything", but ajson doesn't support mapping objects (which is fine, I'd rather have defined ORMs than dynamic maps)
template<typename DataType>
struct DGatewayPayloadDataBase : public DGatewayPayloadBase {
    DataType d;
};
#define GATEWAY_JSON_REQ(DT) AJSON(DGatewayPayloadDataBase<DT>, op, d)

template<typename DataType>
struct DGatewayPayload : public DGatewayPayloadDataBase<DataType> {
    int s;
    std::string t;
};
#define GATEWAY_JSON_RES(DT) AJSON(DGatewayPayload<DT>, op, d, s, t)

/* Now we can define the specific tx interfaces */

struct DGatewayCheck {
    std::string url;
};
AJSON(DGatewayCheck, url);

struct DGatewayHeartbeatData {
    int heartbeat_interval;
};
AJSON(DGatewayHeartbeatData, heartbeat_interval);
GATEWAY_JSON_RES(DGatewayHeartbeatData);

struct DGatewayHeartbeatReq : public DGatewayPayloadDataBase<int> {
    DGatewayHeartbeatReq(int SequenceNum) {
        d = SequenceNum;
        op = (int)DOpcode::HEARTBEAT;
    }
};
GATEWAY_JSON_REQ(int);

struct DGatewayIdentProps {
    std::string $os;
    std::string $browser;
    std::string $device;
};
AJSON(DGatewayIdentProps, $os, $browser, $device);

struct DGatewayIdent {
    DGatewayIdent() {}
    DGatewayIdent(const char* Token) : token(Token) {
        properties.$os = GetOSName();
        properties.$browser = ACCORD_LIB_NAME;
        properties.$device = ACCORD_LIB_NAME;
    }

    std::string token;
    DGatewayIdentProps properties;
};
AJSON(DGatewayIdent, token, properties);
GATEWAY_JSON_REQ(DGatewayIdent);

// some useful typedefs
template<typename DT>
using DGatewayRequest = DGatewayPayloadDataBase<DT>;

template<typename DT>
using DGatewayResponse = DGatewayPayload<DT>;

/**
 * MAIN CLASS
 */

// State object for discord shit
using easywsclient::WebSocket;
class Discord { // there, now we've justified using sepples :^)
    using Self = Discord; // hmm yes

    // Bot-auth properties
    const char* Authorization;
    bool bUsingBearer;
    char AuthHeader[128];

    // Update properties
    double HeartbeatInterval = -1.0;
    double HeartbeatCounter = 0.0;
    int HeartbeatSequenceNum = 0;

    // Time delta
    std::chrono::time_point<std::chrono::high_resolution_clock> OldTime;

    // Eventz!
    DEventSystem<WebSocket::pointer*> EventSystem;

    // our connection instance
    WebSocket::pointer ws;

    // only handle non-unicode sssssss
    DMsgType GetMessageType(char* Format) {
        if (strncmp(Format, "<@!", 3)) return DMsgType::NICK;
        if (strncmp(Format, "<@",  2)) return DMsgType::USER;
        if (strncmp(Format, "<#",  2)) return DMsgType::CHANNEL;
        if (strncmp(Format, "<@&", 3)) return DMsgType::ROLE;
        if (strncmp(Format, "<:",  2)) return DMsgType::EMOJI;
        if (strncmp(Format, "<a:", 3)) return DMsgType::ANIM_EMOJI;

        return DMsgType::MAX; // let the callee sort this out
    }

    WebSocket::pointer GetWSConnection() {
#ifdef NDEBUG
        return WebSocket::from_url(D_GATEWAY_BASE);
#else
        // verify the gateway_base is the same
        httplib::Headers Headers; 
        Headers.emplace("Authorization", AuthHeader);

        httplib::SSLClient cli(D_HOSTNAME);
        std::shared_ptr<httplib::Response> r = cli.Get(D_GATEWAY_BOT_CHECK, Headers);
        if (!!r) {

            DGatewayCheck GatewayCheck;
            ajson::load_from_buff(GatewayCheck, r->body.c_str());

            if (strcmp(GatewayCheck.url.c_str(), D_GATEWAY_BASE) == 0) {
                // matches, we're good
                return WebSocket::from_url(D_GATEWAY_BASE);
            }
            else {
                // we have a new address! We need to change the gateway check constant!
                assert(0);
                return WebSocket::from_url(GatewayCheck.url.c_str());
            }

        }

        assert(0);
        return nullptr; // discord's not having a good day...
    }
#endif

    // Router handlers, just want to separate this from the case statement
    void HandleHello(const std::string& Data) {
        DGatewayPayload<DGatewayHeartbeatData> Payload;
        ajson::load_from_buff(Payload, Data.c_str());

        DEBUG_LOG("Info: heartbeat %d\n", Payload.d.heartbeat_interval);

        // setup the heartbeat properties
        HeartbeatInterval = static_cast<double>(Payload.d.heartbeat_interval);
        HeartbeatCounter = HeartbeatInterval;
        HeartbeatSequenceNum = Payload.s;
        OldTime = std::chrono::high_resolution_clock::now();

        // queue the ident event
        EventSystem.QueueEvent(DEventType::SEND_IDENT);
    }

    void Router(const std::string& Data) {
        DGatewayPayloadBase Payload;
        ajson::load_from_buff(Payload, Data.c_str());

        switch (static_cast<DOpcode>(Payload.op)) {
            case DOpcode::HELLO: HandleHello(Data.c_str()); break;
            default: DEBUG_LOG("Unknown Event: %s", Data.c_str()); break;
        }
    }

    template<typename T>
    std::string Serialize(const T& x) {
        std::stringstream ss;
        ajson::save_to(ss, x);
        return ss.str();
    }

    // Handle anything that needs to be ticked, heartbeat for example
    void Update() {
        assert(ws);

        auto NewTime = std::chrono::high_resolution_clock::now();
        double Delta = (NewTime - OldTime).count() / 1000000.0; // count returns nanoseconds, we want milliseconds

        // Send a heartbeat when needed
        if (HeartbeatInterval > 0.0) {
            HeartbeatCounter -= Delta;

            if (HeartbeatCounter <= 0.0) {
                HeartbeatCounter = HeartbeatInterval;
                EventSystem.QueueEvent(DEventType::SEND_HEARTBEAT);
            }
            
        }

        // we NEED to call this for events to poll
        EventSystem.Update();

        OldTime = NewTime;
    }

public:
    Discord(const char* Token, bool bBearer = false) : Authorization(Token), bUsingBearer(bBearer), EventSystem(&ws) {
        size_t HeaderLen = 0;

        // work out the lens and strcpy the appropriate header preamble
        if (bBearer) {
            HeaderLen += strlen(D_HEADER_BEARER_AUTH);
            strcpy(AuthHeader, D_HEADER_BEARER_AUTH);
        }
        else {
            HeaderLen += strlen(D_HEADER_BOT_AUTH);
            strcpy(AuthHeader, D_HEADER_BOT_AUTH);
        }

        // now copy in the token
        strcpy(AuthHeader+HeaderLen, Token);

        // done!!
        // websocket assignment has to happen after parsing the auth token
        ws = GetWSConnection();

        // Now define discord specific events

        EventSystem.AddEvent(DEventType::SEND_IDENT, [this](WebSocket::pointer* ws){
            DGatewayRequest<DGatewayIdent> Ident;
            Ident.op = (int)DOpcode::IDENT;
            Ident.d = DGatewayIdent(Authorization);

            (*ws)->send(Serialize(Ident));

            DEBUG_LOG("Sent ident!\n");
        });

        EventSystem.AddEvent(DEventType::SEND_HEARTBEAT, [this](WebSocket::pointer* ws){
            DGatewayHeartbeatReq Beat(HeartbeatSequenceNum);

            //std::string str = Serialize(Beat);
            //(*ws)->send(str);

            //DEBUG_LOG("Beat! %s\n", str.c_str());
        });
    }

    // called when you finish setting everything up, almost always at the end of main()
    void Start() {
        while (ws && ws->getReadyState() != WebSocket::readyStateValues::CLOSED) {
            ws->poll();
            ws->dispatch([this](const std::string& Data){ Router(Data); });
            Update();
        }

        DEBUG_LOG("Discord closed the connection.");
    }
};
