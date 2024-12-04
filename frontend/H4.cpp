/////////////////////////////////////////////////////////////////////////////
//// Example source code for blog post:
//// "C++ Coroutines: Understanding Symmetric-Transfer"
////
//// Implementation of a naive 'task' coroutine type.
//
//#include <coroutine>
//#include <iostream>
//#include <utility>
//// using namespace std;
//
//#ifndef H4_H
//#define H4_H
//
//#define H4_VERSION  "4.0.8"
//
//#ifndef H4_USERLOOP
//#define H4_USERLOOP       1 // improves performance
//#endif
//#define H4_COUNT_LOOPS    0 // DIAGNOSTICS
//#define H4_HOOK_TASKS     0
//
//#define H4_JITTER_LO    100 // Entropy lower bound
//#define H4_JITTER_HI    350 // Entropy upper bound
//#define H4_Q_CAPACITY	 10 // Default Q capacity
//#define H4_Q_ABS_MIN      6 // Absolute minimum Q capacity
//
//#define H4_DEBUG          0
//
//#define H4_SAFETY_TIME  200 // ms, the time space where h4 could fix rollover issue, 
//							// too long might let more functions called earler if these falls just between millis() rollover and this period, just after the rollover, 
//							// too tight might cause missing it (if the h4.loop() didn't take control at the short period)
//
//#if H4_DEBUG
//#define H4_Pirntf(f_, ...)    Serial.printf((f_), ##__VA_ARGS__)
//#else
//#define H4_Pirntf(f_, ...)
//#endif
//
//
//enum {
//	H4_CHUNKER_ID = 90,
//	H4AT_SCAVENGER_ID,
//	H4AS_SSE_KA_ID,
//	H4AS_WS_KA_ID,
//	H4AMC_RCX_ID,
//	H4AMC_KA_ID
//}; // must not grow past 99!
//
//// #include <Arduino.h>
//
//#include<algorithm>
//#include<cstdint>
//#include<cstring>
//#include<functional>
//#include<map>
//#include<queue>
//#include<string>
//#include<unordered_map>
//#include<vector>
//#define __PRETTY_FUNCTION__ __FUNCSIG__
//#ifdef ARDUINO_ARCH_RP2040
//#define h4rebootCore rp2040.restart
//#elif defined(ARDUINO)
//#define h4rebootCore ESP.restart
//#else
//void somef() {}
//#define h4rebootCore somef
//#endif
//#define H4_BOARD ARDUINO_BOARD
//
//uint32_t globMillis;
//uint32_t millis() {
//	return globMillis;
//}
//
//void debugFunction(std::string f) { std::cout << f << std::endl; }
//void h4reboot();
//
//void HAL_enableInterrupts();
//void HAL_disableInterrupts();
//
//uint64_t millis64();
//
//
//class   task;
//using	H4_TASK_PTR = task*;
//using	H4_TIMER = H4_TASK_PTR;
//
//class H4Delay;
//struct H4Coroutine {};
//
//using	H4_FN_COUNT = std::function<uint32_t(void)>;
//using	H4_FN_TASK = std::function<void(H4_TASK_PTR, uint32_t)>;
//using	H4_FN_TIF = std::function<bool(H4_TASK_PTR)>;
//using	H4_FN_VOID = std::function<void(void)>;
//using   H4_FN_COROUTINE = std::function<H4Delay(H4Coroutine)>;
//using   H4_FN_RTPTR = H4_FN_COUNT;
////
//using   H4_INT_MAP = std::unordered_map<uint32_t, std::string>;
//using 	H4_TIMER_MAP = std::unordered_map<uint32_t, H4_TIMER>;
////
//
//#define CSTR(x) x.c_str()
//#define ME H4::context
//#define MY(x) H4::context->x
//#define TAG(x) (u+((x)*100))
//
//extern H4_TASK_PTR& H4_context;
//
//class H4Countdown {
//public:
//	uint32_t 	count;
//	H4Countdown(uint32_t start = 1) { count = start; }
//	uint32_t operator()() { return --count; }
//};
//
//class H4Random : public H4Countdown {
//public:
//	H4Random(uint32_t tmin = 0, uint32_t tmax = 0);
//};
//
////
////		T A S K
////
//class task {
//	bool  		    harakiri = false;
//
//	void            _chain();
//	void            _destruct();
//	friend class H4Delay;
//public:
//	uint64_t        id;
//	H4_FN_VOID     	f;
//	H4_FN_COROUTINE fcoro;
//	uint32_t        rmin = 0;
//	uint32_t        rmax = 0;
//	H4_FN_COUNT    	reaper;
//	H4_FN_VOID     	chain;
//	// H4_FN_COROUTINE chaincoro;
//	uint32_t		uid = 0;
//	bool 			singleton = false;
//	H4_FN_VOID      lastRites = [] {};
//	size_t			len = 0;
//	uint64_t        at;
//	uint32_t		nrq = 0;
//	void* partial = NULL;
//
//	bool            operator()(const task* lhs, const task* rhs) const;
//	void            operator()();
//
//	task() {} // only for comparison operator
//
//	task(
//		H4_FN_VOID    	_f,
//		uint32_t		_m,
//		uint32_t		_x,
//		H4_FN_COUNT    	_r,
//		H4_FN_VOID    	_c,
//		uint32_t		_u = 0,
//		bool 			_s = false
//	);
//
//	task(
//		H4_FN_COROUTINE	_f,
//		uint32_t		_m,
//		uint32_t		_x,
//		H4_FN_COUNT    	_r,
//		H4_FN_VOID    	_c,
//		uint32_t		_u = 0,
//		bool 			_s = false
//	);
//
//	~task() {}//H4_Pirntf("T=%u TASK DTOR %p\n",millis(),this); }
//
//	static	void 		cancelSingleton(uint32_t id);
//	uint32_t 	cleardown(uint32_t t);
//	//		The many ways to die... :)
//	uint32_t 	endF(); // finalise: finishEarly
//	uint32_t 	endU(); // unconditional finishNow;
//	uint32_t	endC(H4_FN_TIF); // conditional
//	uint32_t	endK(); // kill, chop etc
//	//
//	void		createPartial(void* d, size_t l);
//	void 		getPartial(void* d) { memcpy(d, partial, len); }
//	void        putPartial(void* d) { memcpy(partial, d, len); }
//	void 		requeue();
//	void 		schedule();
//	static 	uint32_t	randomRange(uint32_t lo, uint32_t hi); // move to h4
//};
//
//class H4Coroutine
//{
//
//	// task* owner;
//	uint32_t duration;
//	task* owner = nullptr;
//	task* resumer = nullptr;
//public:
//	class promise_type {
//		// uint32_t duration;
//		task* owner = nullptr;
//		task* resumer = nullptr;
//		friend class H4Coroutine;
//	public:
//		H4Coroutine get_return_object() noexcept;
//		std::suspend_never initial_suspend() noexcept;
//		void return_void() noexcept;
//		void unhandled_exception() noexcept;
//		struct final_awaiter;
//		final_awaiter final_suspend() noexcept;
//
//		void cancel();
//	};
//	std::coroutine_handle<promise_type> _coro;
//
//	explicit H4Coroutine(std::coroutine_handle<promise_type> h) : _coro(h) { debugFunction(__PRETTY_FUNCTION__); printf("this=%p\n", this); printf("h=%p\n", h.address()); }
//	~H4Coroutine() {
//		debugFunction(__PRETTY_FUNCTION__);
//		// printf("this=%p\n", this);
//		// printf("_coro=%p\tduration=%u\towner=%p\tresumer=%p\n", _coro,duration,owner,resumer);
//		// if (_coro) _coro.destroy();
//	}
//};
//
//class H4Delay {
//	 task* owner;
//	uint32_t duration;
//public:
//
//	explicit H4Delay(uint32_t duration, task* caller = H4_context) : duration(duration), owner(caller) {
//		// debugFunction(__PRETTY_FUNCTION__); printf("this=%p\n", this); 
//		// printf("_coro=%p\tduration=%u\towner=%p\tresumer=%p\n", _coro,duration,owner,resumer);
//	}
//
//	bool await_ready() noexcept;
//	void await_suspend(const std::coroutine_handle<void> h) noexcept;
//	void await_resume() noexcept;
//};
////
////      H 4
////
//
//class H4 : public std::priority_queue<task*, std::vector<task*>, task> { // H4P 35500 - 35700
//	friend class task;
//	H4_TIMER_MAP    singles;
//	std::vector<H4_FN_VOID> loopChain;
//public:
//	std::unordered_map<uint32_t, uint32_t> unloadables;
//	static  H4_TASK_PTR		context;
//	static  std::map<task*, std::coroutine_handle<H4Coroutine::promise_type>> suspendedTasks;
//
//
//	void 		    loop();
//	void            setup();
//
//	H4(uint32_t baud = 0, size_t qSize = H4_Q_CAPACITY) {
//		reserve(qSize);
//		if (baud) {
//			// Serial.begin(baud);
//			H4_Pirntf("\nH4 RUNNING %s\n", H4_VERSION);
//		}
//	}
//
//	H4_TASK_PTR 	every(uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	everyRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	nTimes(uint32_t n, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	nTimesRandom(uint32_t n, uint32_t msec, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR		once(uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	onceRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR		queueFunction(H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	randomTimes(uint32_t tmin, uint32_t tmax, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	randomTimesRandom(uint32_t tmin, uint32_t tmax, uint32_t msec, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	repeatWhile(H4_FN_COUNT w, uint32_t msec, H4_FN_VOID fn = []() {}, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	repeatWhileEver(H4_FN_COUNT w, uint32_t msec, H4_FN_VOID fn = []() {}, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//
//	H4_TASK_PTR 	every(uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	everyRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	nTimes(uint32_t n, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	nTimesRandom(uint32_t n, uint32_t msec, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR		once(uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	onceRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR		queueFunction(H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	randomTimes(uint32_t tmin, uint32_t tmax, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	randomTimesRandom(uint32_t tmin, uint32_t tmax, uint32_t msec, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	repeatWhile(H4_FN_COUNT w, uint32_t msec, H4_FN_COROUTINE fn = [](H4Coroutine) -> H4Delay { return H4Delay(0); }, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//	H4_TASK_PTR 	repeatWhileEver(H4_FN_COUNT w, uint32_t msec, H4_FN_COROUTINE fn = [](H4Coroutine) -> H4Delay { return H4Delay(0); }, H4_FN_VOID fnc = nullptr, uint32_t u = 0, bool s = false);
//
//	H4_TASK_PTR		cancel(H4_TASK_PTR t = context) { return endK(t); } // ? rv ?
//	void			cancel(std::initializer_list<H4_TASK_PTR> l) { for (auto const t : l) cancel(t); }
//	void 			cancelAll(H4_FN_VOID fn = nullptr);
//	void 			cancelSingleton(uint32_t s) { task::cancelSingleton(s); }
//	void			cancelSingleton(std::initializer_list<uint32_t> l) { for (auto const i : l) cancelSingleton(i); }
//	uint32_t 		finishEarly(H4_TASK_PTR t = context) { return endF(t); }
//	uint32_t 		finishNow(H4_TASK_PTR t = context) { return endU(t); }
//	bool			finishIf(H4_TASK_PTR t, H4_FN_TIF f) { return endC(t, f); }
//	//              syscall only
//	size_t          _capacity() { return c.capacity(); }
//	std::vector<task*>   _copyQ();
//	void            _hookLoop(H4_FN_VOID f, uint32_t subid);
//	bool            _unHook(uint32_t token);
//
//	//	protected:
//	uint32_t 		gpFramed(task* t, std::function<uint32_t()> f);
//	bool  			has(task* t) { return find(c.begin(), c.end(), t) != c.end(); }
//	uint32_t		endF(task* t);
//	uint32_t		endU(task* t);
//	bool			endC(task* t, H4_FN_TIF f);
//	task* endK(task* t);
//	void  			qt(task* t);
//	void  			reserve(size_t n) { c.reserve(n); }
//	H4_FN_TASK      taskEvent = [](task*, uint32_t) {};
//	//
//#if H4_HOOK_TASKS
//	static  H4_FN_TASK      taskHook;
//
//	void            _hookTask(H4_FN_TASK f) { taskHook = f; }
//	static  std::string     dumpTask(task* t, uint32_t faze);
//	static  void            addTaskNames(H4_INT_MAP names);
//	static  std::string     getTaskType(uint32_t t);
//	static  const char* getTaskName(uint32_t t);
//#else
//	static  void            addTaskNames(H4_INT_MAP names) {}
//#endif
//	static  void            dumpQ();
//	//    public:
//	task* add(H4_FN_VOID _f, uint32_t _m, uint32_t _x, H4_FN_COUNT _r, H4_FN_VOID _c, uint32_t _u = 0, bool _s = false);
//	task* add(H4_FN_COROUTINE _f, uint32_t _m, uint32_t _x, H4_FN_COUNT _r, H4_FN_VOID _c, uint32_t _u = 0, bool _s = false);
//};
//
//template<typename T>
//class pr {
//	size_t   size = sizeof(T);
//
//	template<typename T2>
//	T2  put(T2 v) {
//		memcpy(MY(partial), reinterpret_cast<void*>(&v), size);
//		return get<T2>();
//	}
//	template<typename T2>
//	T2  get() { return (*(reinterpret_cast<T2*>(MY(partial)))); }
//
//public:
//	pr(T v) {
//		if (!MY(partial)) {
//			MY(partial) = reinterpret_cast<T*>(malloc(size));
//			put<T>(v);
//		}
//	}
//
//	pr operator=(const T other) { return put(other); }
//
//	operator T() { return get<T>(); }
//
//	T operator +(T v) { return get<T>() + v; }
//
//	T operator +=(T v) { return put<T>(get<T>() + v); }
//
//	T* operator->() const {
//		return reinterpret_cast<T*>(MY(partial));
//	}
//};
//
//extern H4 h4;
//
//template<typename T>
//static void h4Chunker(T& x, std::function<void(typename T::iterator)> fn, uint32_t lo = H4_JITTER_LO, uint32_t hi = H4_JITTER_HI, H4_FN_VOID final = nullptr) {
//	H4_TIMER p = h4.repeatWhile(
//		H4Countdown(x.size()),
//		task::randomRange(lo, hi), // arbitrary
//		[=]() {
//			typename T::iterator thunk;
//			ME->getPartial(&thunk);
//			fn(thunk++);
//			ME->putPartial((void*)&thunk);
//			// yield();
//		},
//		final,
//		H4_CHUNKER_ID);
//	typename T::iterator chunkIt = x.begin();
//	p->createPartial((void*)&chunkIt, sizeof(typename T::iterator));
//	p->lastRites = [=] {
//		free(p->partial);
//		p->partial = nullptr;
//		};
//}
//
//#endif // H4_H
//
//#define __attribute__(X) 
//
//////////////////////////// H4.cpp /////////////////////////////
//#ifdef ARDUINO_ARCH_ESP32
//portMUX_TYPE h4_mutex = portMUX_INITIALIZER_UNLOCKED;
//void HAL_enableInterrupts() { portEXIT_CRITICAL(&h4_mutex); }
//void HAL_disableInterrupts() { portENTER_CRITICAL(&h4_mutex); }
//#else
//void HAL_enableInterrupts() { /* interrupts(); */ }
//void HAL_disableInterrupts() { /* noInterrupts(); */ }
//#endif
////
////      and ...here we go!
////
//void __attribute__((weak)) h4setup();
//void __attribute__((weak)) h4UserLoop();
//
//H4_TIMER 		    H4::context = nullptr;
//H4_TASK_PTR& H4_context = H4::context;
//
//std::map<task*, std::coroutine_handle<H4Delay::promise_type>> H4::suspendedTasks;
//
//void h4reboot() { h4rebootCore(); }
//
//H4Random::H4Random(uint32_t rmin, uint32_t rmax) { count = task::randomRange(rmin, rmax); }
//
//__attribute__((weak)) H4_INT_MAP h4TaskNames = {};
//
//#if H4_COUNT_LOOPS
//uint32_t h4Nloops = 0;
//#endif
//
//H4Delay H4Delay::promise_type::get_return_object() noexcept {
//	debugFunction(__PRETTY_FUNCTION__);
//	return H4Delay(std::coroutine_handle<promise_type>::from_promise(*this));
//}
//std::suspend_never H4Delay::promise_type::initial_suspend() noexcept { debugFunction(__PRETTY_FUNCTION__);  return {}; }
//void H4Delay::promise_type::return_void() noexcept { debugFunction(__PRETTY_FUNCTION__); }
//void H4Delay::promise_type::unhandled_exception() noexcept { debugFunction(__PRETTY_FUNCTION__); std::terminate(); }
//struct H4Delay::promise_type::final_awaiter {
//	bool await_ready() noexcept { debugFunction(__PRETTY_FUNCTION__); return false; }
//	bool await_suspend(std::coroutine_handle<promise_type> h) noexcept {
//		debugFunction(__PRETTY_FUNCTION__);
//		printf("h=%p\n", h.address());
//		auto owner = h.promise().owner;
//		if (owner) owner->_destruct();
//		H4::suspendedTasks.erase(owner);
//		// [ ] IF NOT IMMEDIATEREQUEUE: MANAGE REQUEUE AND CHAIN CALLS.
//		return false;
//	}
//	void await_resume() noexcept { debugFunction(__PRETTY_FUNCTION__); }
//};
//H4Delay::promise_type::final_awaiter H4Delay::promise_type::final_suspend() noexcept { return {}; }
//
//bool H4Delay::await_ready() noexcept { debugFunction(__PRETTY_FUNCTION__); return false; }
//
//void H4Delay::await_suspend(const std::coroutine_handle<promise_type> h) noexcept {
//	debugFunction(__PRETTY_FUNCTION__);
//	printf("h=%p\n", h.address());
//	// Schedule the resumer.
//	_coro = h;
//	resumer = h4.once(duration, [this] {
//
//		debugFunction(__PRETTY_FUNCTION__);
//		_coro.resume();
//		});
//	h.promise().owner = owner;
//	h.promise().resumer = resumer;
//	H4::suspendedTasks[owner] = _coro;
//}
//
//void H4Delay::await_resume() noexcept {
//	debugFunction(__PRETTY_FUNCTION__);
//	resumer = nullptr;
//}
//
//
//void H4Delay::promise_type::cancel() {
//	debugFunction(__PRETTY_FUNCTION__);
//	auto _coro = std::coroutine_handle<H4Delay::promise_type>::from_promise(*this);
//	printf("_coro=%p\n", _coro.address());
//	if (_coro) {
//		// _coro.promise().owner = nullptr;
//		_coro.destroy();
//	}
//	if (resumer) {
//		h4.cancel(resumer);
//		resumer = nullptr;
//	}
//	H4::suspendedTasks.erase(owner);
//	owner = nullptr;
//}
//
//
//void H4::dumpQ() {}
//
//uint64_t millis64() {
//	static volatile uint64_t overflow = 0;
//	static volatile uint32_t lastSample = 0;
//	static const uint64_t kOverflowIncrement = static_cast<uint64_t>(0x100000000);
//
//	uint64_t overflowSample;
//	uint32_t sample;
//
//	// Tracking timer wrap assumes that this function gets called with
//	// a period that is less than 1/2 the timer range.
//	HAL_disableInterrupts();
//	sample = millis();
//
//	if (lastSample > sample)
//	{
//		overflow = overflow + kOverflowIncrement;
//	}
//
//	lastSample = sample;
//	overflowSample = overflow;
//	HAL_enableInterrupts();
//
//	return (overflowSample | static_cast<uint64_t>(sample));
//}
////
////		task
////
//task::task(
//	H4_FN_VOID     	_f,
//	uint32_t		_m,
//	uint32_t		_x,
//	H4_FN_COUNT    	_r,
//	H4_FN_VOID     	_c,
//	uint32_t		_u,
//	bool 			_s
//) :
//	f{ _f },
//	rmin{ _m },
//	rmax{ _x },
//	reaper{ _r },
//	chain{ _c },
//	uid{ _u },
//	singleton{ _s }
//{
//	static uint64_t count = 0;
//	count++;
//	id = count;
//	if (_s) {
//		uint32_t id = _u % 100;
//		if (h4.singles.count(id)) h4.singles[id]->endK();
//		h4.singles[id] = this;
//	}
//	schedule();
//}
//task::task(
//	H4_FN_COROUTINE _f,
//	uint32_t		_m,
//	uint32_t		_x,
//	H4_FN_COUNT    	_r,
//	H4_FN_VOID     	_c,
//	uint32_t		_u,
//	bool 			_s
//) :
//	fcoro{ _f },
//	rmin{ _m },
//	rmax{ _x },
//	reaper{ _r },
//	chain{ _c },
//	uid{ _u },
//	singleton{ _s }
//{
//	static uint64_t count = 0;
//	count++;
//	id = count;
//	if (_s) {
//		uint32_t id = _u % 100;
//		if (h4.singles.count(id)) h4.singles[id]->endK();
//		h4.singles[id] = this;
//	}
//	schedule();
//}
//
//bool task::operator() (const task* lhs, const task* rhs) const { return ((lhs->at > rhs->at) || (lhs->at == rhs->at && lhs->id > rhs->id)) ? true : false; }
//H4Coroutine h4dummy;
//void task::operator()() {
//	if (harakiri) _destruct(); // for clean exits
//	else {
//		std::cout << "CALLING " << (f ? "F" : fcoro ? "FCORO" : "UNDEFINED") << std::endl;
//		if (f) f();
//		else fcoro(h4dummy);
//		// f();
//		bool thisis_suspended = H4::suspendedTasks.count(this);
//		// CURRENTLY: THIS ONLY PREVENTS DESTRUCTION AT THIS POINT, IN FUTURE: RELAY REQUEUE & CHAIN ..
//		if (reaper) { // it's finite
//			if (!(reaper())) { // ...and it just ended
//				_chain(); // run chain function if there is one
//				if ((rmin == rmax) && rmin) {
//					rmin = 86400000; // reque in +24 hrs
//					rmax = 0;
//					reaper = nullptr; // and every day after
//					requeue();
//				}
//				else if (!thisis_suspended) _destruct();
//			}
//			else requeue();
//		}
//		else requeue();
//	}
//}
//
//void task::_chain() { if (chain) h4.add(chain, 0, 0, H4Countdown(1), nullptr, uid); } // prevents tag rescaling during the pass
//
//void task::cancelSingleton(uint32_t s) { if (h4.singles.count(s)) h4.singles[s]->endK(); }
//
//uint32_t task::cleardown(uint32_t pass) {
//	if (singleton) {
//		uint32_t id = uid % 100;
//		h4.singles.erase(id);
//	}
//	return pass;
//}
//
//void task::_destruct() {
//	debugFunction(__PRETTY_FUNCTION__);
//#if H4_HOOK_TASKS
//	H4::taskHook(this, 4);
//#endif
//	lastRites();
//	if (partial) free(partial);
//	delete this;
//}
////		The many ways to die... :)
//uint32_t task::endF() {
//	//    H4_Pirntf("ENDF %p\n",this);
//	reaper = H4Countdown(1);
//	at = 0;
//	return cleardown(1 + nrq);
//}
//
//uint32_t task::endU() {
//	//    H4_Pirntf("ENDU %p\n",this);
//	_chain();
//	return nrq + endK();
//}
//
//uint32_t task::endC(H4_FN_TIF f) {
//	bool rv = f(this);
//	if (rv) return endF();
//	return rv;
//}
//
//uint32_t task::endK() {
//	debugFunction(__PRETTY_FUNCTION__);
//	//    H4_Pirntf("ENDK %p\n",this);
//	auto it = std::find_if(H4::suspendedTasks.begin(), H4::suspendedTasks.end(), [this](const std::pair<task*, std::coroutine_handle<H4Delay::promise_type>> p) { return p.first == this; });
//	bool thisiscoro = it != H4::suspendedTasks.end();
//	std::cout << "\tthisiscoro=" << thisiscoro << std::endl;
//	if (thisiscoro) {
//		it->second.promise().cancel();
//	}
//	harakiri = true;
//	return cleardown(at = 0);
//}
//
//uint32_t task::randomRange(uint32_t rmin, uint32_t rmax) { return rmax > rmin ? (rand() % (rmax - rmin)) + rmin : rmin; }
//
//void task::requeue() {
//	nrq++;
//	schedule();
//	h4.qt(this);
//}
//
//void task::schedule() { at = millis64() + randomRange(rmin, rmax); }
//
//void task::createPartial(void* d, size_t l) {
//	partial = malloc(l);
//	memcpy(partial, d, l);
//	len = l;
//}
////
////      H4
////
//task* H4::add(H4_FN_VOID _f, uint32_t _m, uint32_t _x, H4_FN_COUNT _r, H4_FN_VOID _c, uint32_t _u, bool _s) {
//	task* t = new task(_f, _m, _x, _r, _c, _u, _s);
//#if H4_HOOK_TASKS
//	H4::taskHook(t, 1);
//#endif
//	qt(t);
//	return t;
//}
//task* H4::add(H4_FN_COROUTINE _f, uint32_t _m, uint32_t _x, H4_FN_COUNT _r, H4_FN_VOID _c, uint32_t _u, bool _s) {
//	task* t = new task(_f, _m, _x, _r, _c, _u, _s);
//#if H4_HOOK_TASKS
//	H4::taskHook(t, 1);
//#endif
//	qt(t);
//	return t;
//}
//
//uint32_t H4::gpFramed(task* t, H4_FN_RTPTR f) {
//	uint32_t rv = 0;
//	printf("t=%p, f=%p\n", t, f);
//	if (t) {
//		HAL_disableInterrupts();
//		if (has(t) || (t == H4::context) || H4::suspendedTasks.count(t)) rv = f(); // fix bug where context = 0!
//		HAL_enableInterrupts();
//	}
//	return rv;
//}
//
//uint32_t H4::endF(task* t) { return gpFramed(t, [=] { return t->endF(); }); }
//
//uint32_t H4::endU(task* t) { return gpFramed(t, [=] { return t->endU(); }); }
//
//bool 	 H4::endC(task* t, H4_FN_TIF f) { return gpFramed(t, [=] { return t->endC(f); }); }
//
//task* H4::endK(task* t) { 
//	debugFunction(__PRETTY_FUNCTION__); 
//	return reinterpret_cast<task*>(gpFramed(t, [=] { return t->endK(); })); }
//
//void H4::qt(task* t) {
//	HAL_disableInterrupts();
//	push(t);
//	HAL_enableInterrupts();
//#if H4_HOOK_TASKS
//	H4::taskHook(t, 2);
//#endif
//}
////
//extern  void h4setup();
//
//std::vector<task*> H4::_copyQ() {
//	std::vector<task*> t;
//	HAL_disableInterrupts();
//	t = c;
//	HAL_enableInterrupts();
//	return t;
//}
//
//void H4::_hookLoop(H4_FN_VOID f, uint32_t subid) {
//	if (f) {
//		unloadables[subid] = loopChain.size();
//		loopChain.push_back(f);
//	}
//}
//
//bool H4::_unHook(uint32_t subid) {
//	if (unloadables.count(subid)) {
//		loopChain.erase(loopChain.begin() + unloadables[subid]);
//		unloadables.erase(subid);
//		return true;
//	}
//	return false;
//}
//
//void setup() {
//	h4.setup();
//	h4setup();
//}
//
//void loop() {
//	h4.loop();
//}
//
//void H4::cancelAll(H4_FN_VOID f) {
//	HAL_disableInterrupts();
//	while (!empty()) {
//		top()->endK();
//		pop();
//	}
//	HAL_enableInterrupts();
//	if (f) f();
//}
//
//H4_TASK_PTR H4::every(uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, nullptr, fnc, TAG(3), s); }
//
//H4_TASK_PTR H4::everyRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, nullptr, fnc, TAG(4), s); }
//
//H4_TASK_PTR H4::nTimes(uint32_t n, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, H4Countdown(n), fnc, TAG(5), s); }
//
//H4_TASK_PTR H4::nTimesRandom(uint32_t n, uint32_t Rmin, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, H4Countdown(n), fnc, TAG(6), s); }
//
//H4_TASK_PTR H4::once(uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, H4Countdown(1), fnc, TAG(7), s); }
//
//H4_TASK_PTR H4::onceRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, H4Countdown(1), fnc, TAG(8), s); }
//
//H4_TASK_PTR H4::queueFunction(H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, 0, 0, H4Countdown(1), fnc, TAG(9), s); }
//
//H4_TASK_PTR H4::randomTimes(uint32_t tmin, uint32_t tmax, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, H4Random(tmin, tmax), fnc, TAG(10), s); }
//
//H4_TASK_PTR H4::randomTimesRandom(uint32_t tmin, uint32_t tmax, uint32_t Rmin, uint32_t Rmax, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, H4Random(tmin, tmax), fnc, TAG(11), s); }
//
//H4_TASK_PTR H4::repeatWhile(H4_FN_COUNT fncd, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, fncd, fnc, TAG(12), s); }
//
//H4_TASK_PTR H4::repeatWhileEver(H4_FN_COUNT fncd, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) {
//	return add(fn, msec, 0, fncd,
//		std::bind([this](H4_FN_COUNT fncd, uint32_t msec, H4_FN_VOID fn, H4_FN_VOID fnc, uint32_t u, bool s) {
//			fnc();
//			repeatWhileEver(fncd, msec, fn, fnc, u, s);
//			}, fncd, msec, fn, fnc, u, s),
//		TAG(13), s);
//}
//
//H4_TASK_PTR H4::every(uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, nullptr, fnc, TAG(3), s); }
//
//H4_TASK_PTR H4::everyRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, nullptr, fnc, TAG(4), s); }
//
//H4_TASK_PTR H4::nTimes(uint32_t n, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, H4Countdown(n), fnc, TAG(5), s); }
//
//H4_TASK_PTR H4::nTimesRandom(uint32_t n, uint32_t Rmin, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, H4Countdown(n), fnc, TAG(6), s); }
//
//H4_TASK_PTR H4::once(uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, H4Countdown(1), fnc, TAG(7), s); }
//
//H4_TASK_PTR H4::onceRandom(uint32_t Rmin, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, H4Countdown(1), fnc, TAG(8), s); }
//
//H4_TASK_PTR H4::queueFunction(H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, 0, 0, H4Countdown(1), fnc, TAG(9), s); }
//
//H4_TASK_PTR H4::randomTimes(uint32_t tmin, uint32_t tmax, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, H4Random(tmin, tmax), fnc, TAG(10), s); }
//
//H4_TASK_PTR H4::randomTimesRandom(uint32_t tmin, uint32_t tmax, uint32_t Rmin, uint32_t Rmax, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, Rmin, Rmax, H4Random(tmin, tmax), fnc, TAG(11), s); }
//
//H4_TASK_PTR H4::repeatWhile(H4_FN_COUNT fncd, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) { return add(fn, msec, 0, fncd, fnc, TAG(12), s); }
//
//H4_TASK_PTR H4::repeatWhileEver(H4_FN_COUNT fncd, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) {
//	return add(fn, msec, 0, fncd,
//		std::bind([this](H4_FN_COUNT fncd, uint32_t msec, H4_FN_COROUTINE fn, H4_FN_VOID fnc, uint32_t u, bool s) {
//			fnc();
//			repeatWhileEver(fncd, msec, fn, fnc, u, s);
//			}, fncd, msec, fn, fnc, u, s),
//		TAG(13), s);
//}
//
//void H4::setup() {
//}
//
//void H4::loop() {
//	task* t = nullptr;
//	uint64_t now = millis64();
//	HAL_disableInterrupts();
//	if (size()) {
//		if (((int64_t)(top()->at - now)) < 1) {
//			t = top();
//			pop();
//		}
//	}
//	HAL_enableInterrupts();
//	if (t) { // H4P 35000 35100
//		H4::context = t;
//		//        H4_Pirntf("T=%u H4context <-- %p\n",millis(),t);
//		(*t)();
//		//        H4_Pirntf("T=%u H4context --> %p\n",millis(),t);
//		//        dumpQ();
//	};
//	//
//	for (auto const& f : loopChain) f();
//#if H4_USERLOOP
//	h4UserLoop();
//#endif
//#if H4_COUNT_LOOPS
//	h4Nloops++;
//#endif
//}
//
//H4 h4(0);
//int H4main() {
//	setup();
//	// Emulating while(1) loop.
//	while (millis() < 10000) {
//		if (!(millis() % 5))
//			std::cout << " T= " << millis() << "ms" << std::endl;
//		// Each millisecond runs thousands of iterations, simulate a few:
//		for (auto i = 0; i < 20; i++)
//			loop();
//		globMillis++;
//	}
//	return 0;
//}
//
//H4Delay someF() {
//	debugFunction(__PRETTY_FUNCTION__);
//	printf("on 500, awaiting 400 ms:\n");
//	// auto currentContext = H4::context;
//	// h4.once(100, [currentContext]{ debugFunction(__PRETTY_FUNCTION__); h4.cancel(currentContext); });
//	co_await H4Delay(400);
//	printf("400ms awaited!\n");
//}
//void h4setup() {
//	// h4.once(1000, []{ printf("1000ms elapsed\n"); });
// /*    h4.queueFunction([]() ->H4Delay {
//		// for (auto i=0 ; i<20; i++) {
//		//     printf("i=%d\n", i);
//			co_await H4Delay(5);
//		// }
//	}); */
//	/*     h4.queueFunction([](H4Coroutine) -> H4Delay { // Replacement to h4Chunker(vs,[](std::vector<std::string>::iterator it){ printf("Processing [%s]\n", *it.data());}, 100,200);
//			std::vector<std::string> vs {"Hello", "World"};
//			for (auto &v : vs) {
//				printf ("Processing [%s]\n", v.data());
//				co_await H4Delay(task::randomRange(100,200));
//			}
//		});
//		h4.queueFunction([](H4Coroutine) -> H4Delay { // Replacement to h4.nTimes(20, 5, []{ printf("i=%d\n", ME->nrq);});
//			for (auto i = 0; i < 20; i++) {
//				printf("i=%d\n", i);
//				co_await H4Delay(5); // Delay asynchronously :)
//			}
//			printf("Chain Function\n");
//		});
//
//		h4.queueFunction([](H4Coroutine) -> H4Delay { // Replacement to h4.every(100, []{printf("Some processing\n"); });
//			while (true) {
//				printf("Some processing\n");
//				co_await H4Delay(100);
//			}
//		}); */
//	auto context = h4.once(500, someF);
//	h4.once(1000, [context] { debugFunction(__PRETTY_FUNCTION__); h4.cancel(context); });
//}
//void h4UserLoop() {
//
//}
//
///*
//	Coroutines:
//	- co_await H4Delay({$Time});
//		- co_await H4Delay(0) does queue the continuation to the next loop iteration.
//	- The function signature should return H4Delay type instead of void, and can accepts H4Coroutine Parameter.
//	- Finishing the timer can be done by h4.cancel($task) or h4.FinishNow/h4.FinishIf/h4.cancel. Where they all destroy the coroutine handle.
//	- FinishNow/FinishIf would call the chain function, cancel does not.
//	- The chain or requeue of the coroutine gets called immediately, (Not after the coroutine function itself finishes), therefore if some h4.nTimes() function gets called it'd be rescheduled once it call the coroutine function. Also the chain would be scheduled just after calling the last function even if it's a coroutine. and it would co_await.
//
//
// */