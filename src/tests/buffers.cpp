#include <iostream>
#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/range/algorithm/copy.hpp>
#include "buffers.h"
#include "buffer_iterator.h"

template <class Seq>
std::size_t size(const Seq& seq)
{
    std::size_t d = 0;
    for (typename Seq::const_iterator it=seq.begin(); it!=seq.end(); ++it)
        d += boost::asio::buffer_size(*it);
    return d;
}

template<class It>
class randgen
{
    unsigned int seed_;
    boost::iterator_range<It> r_;
  public:
    explicit randgen(boost::iterator_range<It> r, unsigned int seed = gen_seed())
            : seed_(seed),
              r_(r)
    {}

    static unsigned int gen_seed() { return static_cast<unsigned int>(time(NULL)); }
    typename std::iterator_traits<It>::value_type operator()() { return *(r_.begin() + (rand_r(&seed_) % r_.size())); }
};

template <class It>
randgen<It> make_randgen(boost::iterator_range<It> r) { return randgen<It>(r); }

template <class StreamBuf>
void run_streambuf_test()
{
    StreamBuf b;
    assert(b.size() == 0);

    std::size_t q = ystreambuf::chunk_size;
    assert( size(b.prepare(q-2)) == q-2 );
    assert( size(b.prepare(1)) == 1 );
    assert( size(b.prepare(q)) == q );
    assert( size(b.prepare(q+1)) == q+1 );

    assert( size(b.data()) == 0 && 0 == b.size());
    b.commit(1);
    assert( size(b.data()) == 1 && 1 == b.size());
    b.commit(q-1);
    assert( size(b.data()) == q && q == b.size());
    b.commit(1);
    assert( size(b.data()) == q+1 && q+1 == b.size());

    b.consume(1);
    assert( size(b.data()) == q && q == b.size());
    b.consume(q-1);
    assert( size(b.data()) == 1 && 1 == b.size());

    assert( size(b.prepare(2*q-1)) == 2*q-1 );
    b.consume(1);
    assert( size(b.data()) == 0 && 0 == b.size());
    b.commit(q);
    assert( size(b.data()) == q && q == b.size());
    b.commit(q-1);
    assert( size(b.data()) == 2*q-1 && 2*q-1 == b.size());
    b.consume(2*q-1);
    assert( size(b.data()) == 0 && 0 == b.size());
}

template <class StreamBuf>
void run_iterator_test()
{
    StreamBuf b;

    // create a sample data
    boost::array<char, 20000> sample;
    std::generate(sample.begin(), sample.end(),
            make_randgen(boost::as_literal("0123456789")));

    std::copy(sample.begin(), sample.begin() + 12000, ybuffers_begin(b.prepare(12000)));
    b.commit(12000);

    std::copy(sample.begin() + 12000, sample.begin() + 14000, ybuffers_begin(b.prepare(2000)));
    b.commit(1000);

    std::copy(sample.begin() + 13000, sample.begin() + 15000, ybuffers_begin(b.prepare(2000)));
    b.commit(2000);

    std::copy(sample.begin() + 15000, sample.begin() + 20000, ybuffers_begin(b.prepare(5000)));
    b.commit(5000);

    typename StreamBuf::const_buffers_type bufs = b.data();
    assert(boost::equal(boost::make_iterator_range(sample.begin(), sample.end()),
                    boost::make_iterator_range(ybuffers_begin(bufs), ybuffers_end(bufs)))
           );

    assert(ybuffers_end(bufs) - ybuffers_begin(bufs) == 20000);
    assert(ybuffers_begin(bufs) - ybuffers_end(bufs) == -20000);
}

void run_append_test()
{
    ystreambuf b;
    boost::copy(boost::as_literal("Hello, world!"), ybuffers_begin(b.prepare(512)));
    b.commit(13);

    ystreambuf::const_buffers_type mod_bufs;

    // append a subsequence of const_buffers_type
    ystreambuf::const_buffers_type d = b.data();
    ybuffers_iterator<ystreambuf::const_buffers_type> it = ybuffers_begin(d);
    assert(append(it, it+7, mod_bufs) == 7);
    b.consume(7);

    // append a const string literal
    assert(append(shared_const_chunk(new chunk_csl("big ")), mod_bufs) == 4);

    // append a string
    std::string s("BIG ");
    assert(append(shared_const_chunk(new chunk_string(s)), mod_bufs) == 4);

    // once again append a subsequence of const_buffers_type
    d = b.data();
    it = ybuffers_begin(d);
    assert(append(it, it+6, mod_bufs) == 6);
    b.consume(6);

    // verify our destination buffers sequence
    assert(boost::equal(boost::as_literal("Hello, big BIG world!"),
                    boost::make_iterator_range(ybuffers_begin(mod_bufs), ybuffers_end(mod_bufs)))
           );
    b.consume(b.size());

    // buffers copy test
    std::string header = "Subject: hello\r\n";
    std::string body = "there\r\n";
    std::string message = header + "\r\n" + body;
    boost::copy(boost::as_literal(header), ybuffers_begin(b.prepare(header.size())));
    b.commit(header.size());
    boost::copy(boost::as_literal(body), ybuffers_begin(b.prepare(body.size())));
    b.commit(body.size());

    ystreambuf::const_buffers_type hbufs, bufs;
    assert(b.size() == header.size() + body.size());
    d = b.data();
    append(ybuffers_begin(d), ybuffers_begin(d) + header.size(), hbufs);
    append(hbufs.begin(), hbufs.end(), bufs);
    append("\r\n", bufs);
    append(ybuffers_begin(d) + header.size(), ybuffers_end(d), bufs);
    assert(boost::equal(message,
                    boost::make_iterator_range(ybuffers_begin(bufs), ybuffers_end(bufs)))
           );
    b.consume(b.size());
}

void run_ptrend_test()
{
    // create a sample data
    boost::array<char, 20000> sample;
    std::generate(sample.begin(), sample.end(),
            make_randgen(boost::as_literal("0123456789")));

    ystreambuf b;
    std::copy(sample.begin(), sample.end(), ybuffers_begin(b.prepare(sample.size())));
    b.commit(sample.size());

    ystreambuf::const_buffers_type bufs = b.data();
    ybuffers_iterator<ystreambuf::const_buffers_type> bb = ybuffers_begin(bufs);
    ybuffers_iterator<ystreambuf::const_buffers_type> ee = ybuffers_end(bufs);

    const char* d = sample.data();
    while (bb != ee)
    {
        const char* b = &*bb;
        const char* e = ptr_end(bb, ee);
        std::ptrdiff_t block_size = e - b;
        assert(boost::equal(boost::make_iterator_range(b, e),
                        boost::make_iterator_range(d, d + block_size))
               );
        d += block_size;
        bb += block_size;
    }
    assert(d == sample.data() + sample.size());
}

int main()
{
    std::cout << "testing boost::asio::streambuf..." << std::endl;
    run_streambuf_test<boost::asio::streambuf>();

    std::cout << "testing ystreambuf..." << std::endl;
    run_streambuf_test<ystreambuf>();

    std::cout << "testing iterators for boost::asio::streambuf..." << std::endl;
    run_iterator_test<boost::asio::streambuf>();

    std::cout << "testing iterators for ystreambuf..." << std::endl;
    run_iterator_test<ystreambuf>();

    std::cout << "testing append for ystreambuf..." << std::endl;
    run_append_test();

    std::cout << "testing ptr_end for ystreambuf..." << std::endl;
    run_ptrend_test();

    return 0;
}
