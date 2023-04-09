#include <iostream>
#include <chrono>
#include <string>
#include <system_error>
#include <vector>


#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


using clock_type = std::chrono::high_resolution_clock;

class posix_file {
public:
	posix_file(const std::string& filename, std::size_t size, bool direct = false);
	~posix_file() noexcept;

	posix_file(const posix_file&) = delete;
	posix_file(posix_file&&) = delete;
	posix_file& operator=(const posix_file&) = delete;
	posix_file& operator=(posix_file&&) = delete;

	template<class T>
	void consume(const T* arr, std::size_t size) {
		if (write(fd_, reinterpret_cast<const void*>(arr), size * sizeof(T)) < 0)
			throw std::system_error(errno, std::system_category());
	}
private:
	int fd_;
};

posix_file::posix_file(const std::string& filename, std::size_t size, bool direct):
	fd_{open(filename.c_str(), O_TRUNC | O_RDWR | O_CREAT | (direct ? O_DIRECT : 0), 0644)} {

	if (fd_ < 0)
		throw std::system_error(errno, std::system_category());

	if (fallocate(fd_, 0, 0, size) < 0)	
		throw std::system_error(errno, std::system_category());
}

posix_file::~posix_file() {
	close(fd_);
}

class write_bench_base {
private:
	std::size_t size_;
	std::vector<std::uint8_t> data_;

public:
	struct bench_point {
		clock_type::time_point timestamp;
		std::size_t bytes;
	};

	write_bench_base(std::size_t object_size, std::size_t size);
	virtual ~write_bench_base() = 0;

	virtual std::vector<bench_point> run() = 0;

	inline std::size_t size() const { return size_; }
	inline const auto& data() const { return data_; }
};

write_bench_base::write_bench_base(std::size_t object_size, std::size_t size):
	size_{size},
	data_(object_size, 0x55) {
}

write_bench_base::~write_bench_base() = default;

class write_bench_write:
	public write_bench_base {
private:
	bool direct_;

public:
	write_bench_write(std::size_t object_size, std::size_t size, bool direct = false);

	std::vector<bench_point> run() override;
};

write_bench_write::write_bench_write(std::size_t object_size, std::size_t size, bool direct):
	write_bench_base(object_size, size),
	direct_{direct} {}

std::vector<write_bench_base::bench_point> write_bench_write::run() {
	std::vector<bench_point> res;
	res.reserve(size() + 1);

	{

	posix_file target{std::string("/mnt/test.bin"), size() * data().size(), direct_};

	for (std::size_t i = 0; i < size(); ++i) {
		res.emplace_back(bench_point{clock_type::now(), i * data().size()});

		target.consume(data().data(), data().size());
	}

	} // target

	res.emplace_back(bench_point{clock_type::now(), size() * data().size()});

	return res;
}

class write_bench_write_direct:
	public write_bench_write {
public:
	write_bench_write_direct(std::size_t object_size, std::size_t size);
};

write_bench_write_direct::write_bench_write_direct(std::size_t object_size, std::size_t size):
	write_bench_write(object_size, size, true) {}


int main(int argc, char** argv) {
	constexpr std::size_t objects = 3 * 1024;
	constexpr std::size_t object_size = 1024 * 1024 * 16;

	write_bench_write bench{object_size, objects};

	const auto res = bench.run();

	for (const auto x : res) {
		std::cerr << std::chrono::duration_cast<std::chrono::duration<double>>(x.timestamp - res.front().timestamp).count() << " " << x.bytes << std::endl;
	}

	return 0;
}
