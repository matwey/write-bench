#include <iostream>
#include <ratio>
#include <chrono>
#include <cstring>
#include <string>
#include <system_error>
#include <memory>
#include <vector>

#include <boost/align/aligned_allocator.hpp>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <liburing.h>


using clock_type = std::chrono::high_resolution_clock;

class posix_file {
public:
	struct mmap_deleter {
		void operator() (std::uint8_t* addr) {
			msync(reinterpret_cast<void*>(addr), length_, MS_SYNC);
			munmap(reinterpret_cast<void*>(addr), length_);
		}

		std::size_t length_;
	};

	using mmap_ptr = std::unique_ptr<std::uint8_t[], mmap_deleter>;

	posix_file(const std::string& filename, std::size_t size, bool direct = false, bool advice = false);
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

	mmap_ptr map();

	operator int() const noexcept {
		return fd_;
	}
private:
	int fd_;
};

posix_file::posix_file(const std::string& filename, std::size_t size, bool direct, bool advice):
	fd_{open(filename.c_str(), O_TRUNC | O_RDWR | O_CREAT | (direct ? O_DIRECT : 0), 0644)} {

	if (fd_ < 0)
		throw std::system_error(errno, std::system_category());

	if (fallocate(fd_, 0, 0, size) < 0)	
		throw std::system_error(errno, std::system_category());

	if (advice && (posix_fadvise(fd_, 0, size, POSIX_FADV_SEQUENTIAL | POSIX_FADV_DONTNEED | POSIX_FADV_NOREUSE) < 0))
		throw std::system_error(errno, std::system_category());
}

posix_file::mmap_ptr posix_file::map() {
	struct statx sx;

	if (statx(fd_, "", AT_EMPTY_PATH, STATX_SIZE, &sx) < 0)
		throw std::system_error(errno, std::system_category());

	std::size_t size = sx.stx_size;

	void* addr = mmap(NULL, size, PROT_WRITE, MAP_SHARED, fd_, 0);
	if (addr == NULL)
		throw std::system_error(errno, std::system_category());

	return mmap_ptr(reinterpret_cast<std::uint8_t*>(addr), mmap_deleter{size});
}

posix_file::~posix_file() {
	close(fd_);
}

class uring {
public:
	uring(unsigned int entries, unsigned int flags);
	uring(const uring&) = delete;
	uring(uring&&) = delete;
	uring& operator=(const uring&) = delete;
	uring& operator=(uring&&) = delete;
	~uring();

	void register_fd(int fd);
	void register_buffer(const void* buf, std::size_t size);
	operator struct io_uring* () noexcept;

private:
	struct io_uring ring_;
};

uring::uring(unsigned int entries, unsigned int flags) {
	int ret = 0;

	ret = io_uring_queue_init(entries, &ring_, flags);
	if (ret < 0)
		throw std::system_error(-ret, std::system_category());

	ret = io_uring_register_ring_fd(&ring_);
	if (ret < 0)
		throw std::system_error(-ret, std::system_category());
}

uring::~uring() {
	io_uring_queue_exit(&ring_);
}

void uring::register_fd(int fd) {
	int ret = io_uring_register_files(&ring_, &fd, 1);
	if (ret < 0)
		throw std::system_error(-ret, std::system_category());
}

void uring::register_buffer(const void* buf, std::size_t size) {
	struct iovec iov;
	iov.iov_base = const_cast<void*>(buf);
	iov.iov_len = size;

	int ret = io_uring_register_buffers(&ring_, &iov, 1);
	if (ret < 0)
		throw std::system_error(-ret, std::system_category());
}

uring::operator struct io_uring* () noexcept {
	return &ring_;
}

class write_bench_base {
private:
	std::size_t size_;
	std::vector<std::uint8_t, boost::alignment::aligned_allocator<std::uint8_t, 4096>> data_;

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
	bool advice_;

public:
	write_bench_write(std::size_t object_size, std::size_t size, bool direct = false, bool advice = false);

	std::vector<bench_point> run() override;
};

write_bench_write::write_bench_write(std::size_t object_size, std::size_t size, bool direct, bool advice):
	write_bench_base(object_size, size),
	direct_{direct},
	advice_{advice} {}

std::vector<write_bench_base::bench_point> write_bench_write::run() {
	std::vector<bench_point> res;
	res.reserve(size() + 1);

	{

	posix_file target{std::string("/mnt/test.bin"), size() * data().size(), direct_, advice_};

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

class write_bench_write_advice:
	public write_bench_write {
public:
	write_bench_write_advice(std::size_t object_size, std::size_t size);
};

write_bench_write_advice::write_bench_write_advice(std::size_t object_size, std::size_t size):
	write_bench_write(object_size, size, false, true) {}

class write_bench_mmap:
	public write_bench_base {
public:
	write_bench_mmap(std::size_t object_size, std::size_t size);

	std::vector<bench_point> run() override;
};

write_bench_mmap::write_bench_mmap(std::size_t object_size, std::size_t size):
	write_bench_base(object_size, size) {}

std::vector<write_bench_base::bench_point> write_bench_mmap::run() {
	std::vector<bench_point> res;
	res.reserve(size() + 1);

	{

	posix_file target{std::string("/mnt/test.bin"), size() * data().size()};
	auto target_ptr = target.map();

	for (std::size_t i = 0; i < size(); ++i) {
		res.emplace_back(bench_point{clock_type::now(), i * data().size()});

		std::memcpy(target_ptr.get() + i * data().size(), data().data(), data().size());
	}

	} // target

	res.emplace_back(bench_point{clock_type::now(), size() * data().size()});

	return res;
}

class write_bench_uring:
	public write_bench_base {
private:
	unsigned int entries_;
	bool direct_;

public:
	write_bench_uring(std::size_t object_size, std::size_t size, unsigned int entries, bool direct = false);

	std::vector<bench_point> run() override;
};

write_bench_uring::write_bench_uring(std::size_t object_size, std::size_t size, unsigned int entries, bool direct):
	write_bench_base(object_size, size),
	entries_{entries},
	direct_{direct} {}

std::vector<write_bench_base::bench_point> write_bench_uring::run() {
	std::vector<bench_point> res;
	res.reserve(size() + 1);

	{
	uring r{entries_, IORING_SETUP_SINGLE_ISSUER};
	posix_file target{std::string("/mnt/test.bin"), size() * data().size(), direct_};
	r.register_fd(target);
	r.register_buffer(data().data(), data().size());

	res.emplace_back(bench_point{clock_type::now(), 0});

	std::size_t in_flight = 0;
	for (std::size_t i = 0; i < size() || in_flight > 0;) {
		for (; i < size() && in_flight < entries_; ++i, ++in_flight) {
			struct io_uring_sqe *sqe = io_uring_get_sqe(r);
		//	io_uring_prep_write(sqe, 0 /* registered file */, data().data(), data().size(), i * data().size());
			io_uring_prep_write_fixed(sqe, 0 /* registered file */, data().data(), data().size(), i * data().size(), 0 /* registered buffer */);
			io_uring_sqe_set_data64(sqe, i);
			io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
		}

		int ret = io_uring_submit_and_wait(r, 1);
		if (ret < 0)
			throw std::system_error(-ret, std::system_category());

		struct io_uring_cqe *cqe;

		while (io_uring_peek_cqe(r, &cqe) == 0) {
			if (cqe->res < 0)
				throw std::system_error(-cqe->res, std::system_category());

			io_uring_cqe_seen(r, cqe);

			--in_flight;
		}

		res.emplace_back(bench_point{clock_type::now(), (i - in_flight) * data().size()});
	}

	} // target

	return res;
}

int main(int argc, char** argv) {
	constexpr std::size_t objects = 3 * 1024;
	constexpr std::size_t object_size = 1024 * 1024 * 16;

	using write_bench_type = write_bench_uring;

	write_bench_type bench{object_size, objects, 1 << 4, true};

	const auto res = bench.run();

	for (const auto x : res) {
		std::cerr << std::chrono::duration_cast<std::chrono::duration<double, std::micro>>(x.timestamp - res.front().timestamp).count() << " " << x.bytes << std::endl;
	}

	return 0;
}
