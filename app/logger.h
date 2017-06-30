#ifndef __LOGGER_H__
#define __LOGGER_H__

#define __LOG(out, level, fmt, ...) \
	do { \
		fprintf(out, "["#level"] ["__FILE__":%d] (%s) - "fmt"\n", \
				__LINE__, __func__, ##__VA_ARGS__); \
	} while (0)

#define LOG_INFO(fmt, ...)	__LOG(stdout, INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)	__LOG(stderr, WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)	__LOG(stderr, ERROR, fmt, ##__VA_ARGS__)

#if DEBUG
#define LOG_DEBUG(fmt, ...) __LOG(stderr, DEBUG, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(...) do {} while (0)
#endif

#endif /* !__LOGGER_H__ */
