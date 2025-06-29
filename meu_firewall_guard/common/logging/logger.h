#pragma once

// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  logger.h
/// Abstract:  a class that handle the logging logic
/// </summary>
// --------------------------------------------------------------------------------

namespace logging {
	class Logger {
	public:
		enum class state
		{
			stopped,
			starting,
			running,
			stopping
		};


	private:
		/// <summary> queue that store log to process </summary>
		std::queue<std::pair<INTERMEDIATE_BUFFER, u_short>> in_queue;
		/// <summary> mutex for the queue </summary>
		std::mutex qMutex;
		/// <summary> condition variable for the queue </summary>
		std::condition_variable logCV;

		/// <summary> logging thread object </summary>
		std::thread processThread;
		/// <summary> Data Access Object for log table </summary>
		database::LogDAO logDAO;
		/// <summary> current state of the logger </summary>
		state loggerState = state::stopped;

		// ********************************************************************************
		/// <summary>
		/// logger thread routine
		/// </summary>
		// ********************************************************************************
		void loggerProcessThread();

		// ********************************************************************************
		/// <summary>
		/// initialize the working thread/logger
		/// </summary>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool initLogger();


	public:

		Logger() { initLogger(); }
		~Logger() { stopLogger(); }

		// ********************************************************************************
		/// <summary>
		/// insert the logs into a queue outside the working thread
		/// </summary>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool insertLog(INTERMEDIATE_BUFFER buffer, u_short rule_id);

		// ********************************************************************************
		/// <summary>
		/// stops the working thread/logger
		/// </summary>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool stopLogger();
	};

	inline void Logger::loggerProcessThread() {
		while (loggerState == state::running) {

			std::unique_lock<std::mutex> lock(qMutex);

			// Wait until the queue is not empty or logger is stopping
			logCV.wait(lock, [this] {
				return !in_queue.empty() || loggerState != state::running;
				});

			// If stopping and queue is empty, break
			if (loggerState != state::running && in_queue.empty())
				break;

			std::pair<INTERMEDIATE_BUFFER, u_short> rslt = in_queue.front();
			in_queue.pop();
			lock.unlock();
			try {
				logDAO.insertLog(rslt.first, rslt.second);
			}
			catch (std::runtime_error e) {
				std::cout << e.what() << '\n';
			}
			catch (std::exception e) {
				std::cout << e.what() << '\n';
			}
			
		}
	}

	inline bool Logger::initLogger() {
		if (loggerState != state::stopped) return false;

		loggerState = state::running;
		processThread = std::thread(&Logger::loggerProcessThread, this);

		return true;

	}

	inline bool Logger::stopLogger() {
		if (loggerState != state::running) return false;

		loggerState = state::stopping;

		//wake up the logger thread if it's waiting
		logCV.notify_one();

		//wait for working threads to exit
		if (processThread.joinable())
			processThread.join();

		loggerState = state::stopped;
		return true;
	}

	inline bool Logger::insertLog(INTERMEDIATE_BUFFER buffer, u_short rule_id) {
		if (loggerState != state::running) return false;
		
		{
			std::lock_guard<std::mutex> lock(qMutex);
			in_queue.push({ buffer, rule_id });
		}
		logCV.notify_one(); 

		return true;
	}
}