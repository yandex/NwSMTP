#ifndef BUFFER_SEQUENCE_H
#define BUFFER_SEQUENCE_H

#include <boost/asio.hpp>
#include <deque>
#include <boost/range.hpp>
#include <limits>
#include <exception>
#include "buffer_iterator.h"

// Models read-only data container that actually owns the underlying data. Meets ConvertibleToConstBuffer requirements.
class const_chunk
{
  public:
    typedef char value_type;
    typedef const value_type* const_iterator;
    typedef boost::iterator_range<const_iterator> const_iterator_range;

    const_iterator begin() const { return const_range().begin(); }
    const_iterator end() const { return const_range().end(); }

    std::size_t size() const { return const_range().size(); }
    const value_type* const_data() const { return &*const_range().begin(); }

    virtual ~const_chunk() {}
    virtual const_iterator_range const_range() const = 0;

    operator boost::asio::const_buffer() const
    {
        const_iterator_range r = const_range();
        return boost::asio::const_buffer(&*r.begin(), r.size());
    }
};

// Models data container that actually owns the underlying data. Meets ConvertibleToMutableBuffer requirements.
class mutable_chunk : public const_chunk
{
  public:
    typedef value_type* iterator;
    typedef boost::iterator_range<iterator> iterator_range;

    iterator begin() const { return range().begin(); }
    iterator end() const { return range().end(); }

    value_type* data() const { return &*range().begin(); }

    virtual ~mutable_chunk() {}
    virtual iterator_range range() const = 0;

    operator boost::asio::mutable_buffer() const
    {
        iterator_range r = range();
        return boost::asio::mutable_buffer(&*r.begin(), r.size());
    }
};

// Chunk wrapping an array of fixed size.
template <int N>
class chunk_array : public mutable_chunk
{
  public:
    typedef boost::array<value_type, N> container;

    chunk_array() {}
    explicit chunk_array(container& cont) { cont.swap(cont_); }

    virtual iterator_range range() const { return iterator_range(cont_.begin(), cont_.end()); }
    virtual const_iterator_range const_range() const { return iterator_range(cont_.begin(), cont_.end()); }

  private:
    mutable container cont_;
};

// Read-only chunk wrapping a string
class chunk_string : public  const_chunk
{
  public:
    typedef std::string container;

    explicit chunk_string(container& cont) { cont.swap(cont_); }
    virtual const_iterator_range const_range() const { return const_iterator_range(cont_.data(), cont_.data() + cont_.size()); }

  private:
    container cont_;
};

// Read-only chunk wrapping a const string literal
class chunk_csl : public const_chunk
{
  public:
    chunk_csl(const value_type* beg, const value_type* end) : r_(beg, end) {}
    explicit chunk_csl(const value_type* ptr) : r_(ptr, ptr + ::strlen(ptr)) {}
    virtual const_iterator_range const_range() const { return r_; }

  private:
    const_iterator_range r_;
};

// Mutable chunk wrapper that acts as a view of a subrange of the underlying data and shares its ownership. Meets ConvertibleToMutableBuffer requirements.
class shared_mutable_chunk
{
  public:
    typedef mutable_chunk container;
    typedef boost::shared_ptr<container> container_ptr;
    typedef container::value_type value_type;
    typedef container::iterator iterator;
    typedef iterator const_iterator;

    shared_mutable_chunk(container* ptr) : ptr_(ptr), b_(ptr_->begin()), e_(ptr_->end()) {}
    shared_mutable_chunk(container* ptr, iterator b, iterator e) : ptr_(ptr), b_(b), e_(e) { validate_range(); }

    shared_mutable_chunk(const container_ptr& ptr) : ptr_(ptr), b_(ptr_->begin()), e_(ptr_->end()) {}
    shared_mutable_chunk(const container_ptr& ptr, iterator b, iterator e) : ptr_(ptr), b_(b), e_(e) { validate_range(); }

    shared_mutable_chunk(const shared_mutable_chunk& rh) : ptr_(rh.ptr_), b_(rh.b_), e_(rh.e_) {}
    shared_mutable_chunk(const shared_mutable_chunk& rh, iterator b, iterator e) : ptr_(rh.ptr_), b_(b), e_(e) { validate_range(); }

    operator boost::asio::mutable_buffer() const { return boost::asio::mutable_buffer(b_, e_ - b_); }

    iterator begin() const { return b_; }
    iterator end() const { return e_; }

    std::size_t size() const { return e_ - b_; }
    container* get() { return ptr_.get(); }

    // Change the view of the underlying data chunk by moving the boundaries of the viewing subrange
    void slide(int left, int right = 0)
    {
        b_ += left;
        e_ += right;
        validate_range();
    }

  private:
    void validate_range()
    {
        if (b_ < ptr_->begin() || e_ > ptr_->end())
            throw std::out_of_range("iterator range out of bounds");
    }

    container_ptr ptr_;
    iterator b_;
    iterator e_;
    friend class shared_const_chunk;
};

// Const chunk wrapper that acts as a view of a subrange of the underlying data and shares its ownership. Meets ConvertibleToConstBuffer requirements.
class shared_const_chunk
{
  public:
    typedef const_chunk container;
    typedef boost::shared_ptr<container> container_ptr;
    typedef container::value_type value_type;
    typedef container::const_iterator const_iterator;

    shared_const_chunk(container* ptr) : ptr_(ptr), b_(ptr_->begin()), e_(ptr_->end()) {}
    shared_const_chunk(container* ptr, const_iterator b, const_iterator e) : ptr_(ptr), b_(b), e_(e) { validate_range(); }

    shared_const_chunk(const container_ptr& ptr) : ptr_(ptr), b_(ptr_->begin()), e_(ptr_->end()) {}
    shared_const_chunk(const container_ptr& ptr, const_iterator b, const_iterator e) : ptr_(ptr), b_(b), e_(e) { validate_range(); }

    shared_const_chunk(const shared_const_chunk& rh) : ptr_(rh.ptr_), b_(rh.b_), e_(rh.e_) {}
    shared_const_chunk(const shared_const_chunk& rh, const_iterator b, const_iterator e) : ptr_(rh.ptr_), b_(b), e_(e) { validate_range(); }

    shared_const_chunk(const shared_mutable_chunk& rh) : ptr_(rh.ptr_), b_(rh.b_), e_(rh.e_) {}

    operator boost::asio::const_buffer() const { return boost::asio::const_buffer(b_, e_ - b_); }

    const_iterator begin() const { return b_; }
    const_iterator end() const { return e_; }

    std::size_t size() const { return e_ - b_; }
    const container* get() const { return ptr_.get(); }

    // Change the view of the underlying data chunk by moving the boundaries of the viewing subrange
    void slide(int left, int right = 0)
    {
        b_ += left;
        e_ += right;
        validate_range();
    }

  private:
    void validate_range()
    {
        if (b_ < ptr_->begin() || e_ > ptr_->end())
            throw std::out_of_range("iterator range out of bounds");
    }

    container_ptr ptr_;
    const_iterator b_;
    const_iterator e_;
};

// This class implements the public interface of asio::streambuf except for std::streambuf part.
class ystreambuf
{
  public:
    typedef std::deque<shared_mutable_chunk> mutable_buffers_type;
    typedef std::deque<shared_const_chunk> const_buffers_type;

    enum { chunk_size = 16384 };

    ystreambuf() : osize_(0), isize_(0) {}

    // Get a list of buffers that represents the output sequence, with the given size.
    mutable_buffers_type prepare(std::size_t n)
    {
        std::size_t n_saved = n;
        n -= std::min(n, osize_);

        if (osize_ + n > max_size())
            throw std::length_error("ystreambuf too long");

        if (n > 0 && o_.empty())
            prepare_helper(n);

        while (n > 0)
        {
            shared_mutable_chunk& v = o_.back();
            std::size_t sz = v.get()->end() - v.end();
            if (sz == 0)
            {
                prepare_helper(n);
            }
            else
            {
                std::size_t k = std::min(n, sz);
                v.slide(0, k);
                osize_ += k;
                n -= k;
            }
        }

        return (osize_ == n_saved) ? o_ : prefix(o_, n_saved);
    }

    // Get the size of the input sequence.
    std::size_t size() const  { return isize_; }

    // Get the maximum size of the chunked_streambuf.
    std::size_t max_size() const { return std::numeric_limits<std::size_t>::max(); }

    // Get a list of buffers that represents the input sequence.
    const_buffers_type data() const { return i_; }

    // Move characters from the output sequence to the input sequence.
    void commit(std::size_t n)
    {
        if (n > osize_)
            throw std::out_of_range("invalid length to commit requested");

        // We can optimise if the end of the input sequence and the start of the output sequence share the same chunk.
        if (n > 0 && !i_.empty())
        {
            shared_mutable_chunk& v = o_.front();
            shared_const_chunk& vv = i_.back();
            if (vv.get() == v.get())
            {
                std::size_t k = std::min(n, v.size());
                v.slide(k);
                vv.slide(0, k);
                commit_helper(n, k);
                if (v.size() == 0 && n > 0)
                    o_.pop_front();
            }
        }

        while (n > 0)
        {
            shared_mutable_chunk& v = o_.front();
            std::size_t sz = v.size();
            if (n > sz)
            {
                // Move the whole chunk from the output sequence to the input sequence.
                i_.push_back(v);
                o_.pop_front();
                commit_helper(n, sz);
            }
            else
            {
                // Make the chunk shared between the output sequence and the input sequence.
                i_.push_back(shared_const_chunk(v, v.begin(), v.begin() + n));
                v.slide(n);
                commit_helper(n, n);
            }
        }
    }

    // Remove characters from the input sequence.
    void consume(std::size_t n)
    {
        if (n > isize_)
            throw std::out_of_range("invalid length to consume requested");

        while (n > 0)
        {
            shared_const_chunk& vv = i_.front();
            if (vv.size() > n)
            {
                vv.slide(n);
                isize_ -= n;
                n = 0;
            }
            else
            {
                isize_ -= vv.size();
                n -= vv.size();
                i_.pop_front();
            }
        }
    }

  private:
    template <class Seq>
    static Seq prefix(const Seq& seq, std::size_t n)
    {
        typename Seq::const_iterator it = seq.begin();
        Seq d;
        while (n > 0)
        {
            const typename Seq::value_type& v = *it++;
            std::size_t k = std::min(n, v.size());
            n -= k;
            d.push_back(typename Seq::value_type(v, v.begin(), v.begin()+k));
        }
        return d;
    }

    void prepare_helper(std::size_t& n)
    {
        shared_mutable_chunk::container_ptr ptr(new chunk_array<chunk_size>);
        if (n < chunk_size)
        {
            o_.push_back(shared_mutable_chunk(ptr, ptr->begin(), ptr->begin() + n));
            osize_ += n;
            n = 0;
        }
        else
        {
            o_.push_back(shared_mutable_chunk(ptr));
            osize_ += chunk_size;
            n -= chunk_size;
        }
    }

    inline void commit_helper(std::size_t& n, std::size_t k)
    {
        isize_ += k;
        osize_ -= k;
        n -= k;
    }

    mutable_buffers_type o_;  // output sequence
    const_buffers_type i_;    // input sequence
    std::size_t osize_;       // size of the output subsequence
    std::size_t isize_;       // size of the input subsequence
};

template <typename BufferSequence>
inline std::ptrdiff_t append(const typename BufferSequence::value_type& v,
        BufferSequence& seq)
{
    seq.push_back(v);
    return v.size();
}

template <typename BufferSequence>
inline std::ptrdiff_t append(const char* str, BufferSequence& seq)
{
    const typename BufferSequence::value_type v(new chunk_csl(str));
    seq.push_back(v);
    return v.size();
}

template <typename BufferSequence>
inline std::ptrdiff_t append(std::string& str, BufferSequence& seq)
{
    const typename BufferSequence::value_type v(new chunk_string(str));
    seq.push_back(v);
    return v.size();
}

template <typename BufferSequence>
inline std::ptrdiff_t append(const std::string& str, BufferSequence& seq)
{
    std::string d (str);
    const typename BufferSequence::value_type v(new chunk_string(d));
    seq.push_back(v);
    return v.size();
}

template <typename BufferSequence>
inline std::ptrdiff_t append(typename BufferSequence::const_iterator b,
        const typename BufferSequence::const_iterator& e,
        BufferSequence& seq)
{
    std::ptrdiff_t n = 0;
    while (b != e)
    {
        n += boost::asio::buffer_size(*b);
        seq.push_back(*b++);
    }
    return n;
}

template <typename BufferSequence>
std::ptrdiff_t append(ybuffers_iterator<BufferSequence> b,
        const ybuffers_iterator<BufferSequence>& e,
        BufferSequence& seq)
{
    std::ptrdiff_t n = 0;

    typedef typename BufferSequence::const_iterator const_iterator;
    typedef typename BufferSequence::value_type value_type;

    if (e == b)
        return 0;

    // Handle the first buffer as a special case
    std::pair<const_iterator, std::size_t> pb = b.position();
    const_iterator bb = pb.first;
    std::pair<const_iterator, std::size_t> pe = e.position();
    const_iterator ee = pe.first;
    value_type v (*bb, bb->begin() + pb.second,
            bb == ee ? bb->begin() + pe.second : bb->end());

    if (!seq.empty()
            && v.get() == seq.back().get()
            && seq.back().end() == v.begin())
        seq.back().slide(0, v.size());
    else
        seq.push_back(v);
    n += v.size();
    if (bb++ == ee)
        return n;

    // Handle the rest of the buffers but the last
    while (bb != ee)
    {
        const value_type& v = *bb++;
        seq.push_back(v);
        n += v.size();
    }

    // Handle the last buffer
    if (pe.second != 0)
    {
        seq.push_back(value_type(*ee, ee->begin(), ee->begin() + pe.second));
        n += pe.second;
    }

    return n;
}

// Returns a raw pointer to the end of the first continuous data block referenced by the iterator range
template <typename BufferSequence>
inline const char* ptr_end(const ybuffers_iterator<BufferSequence>& b, const ybuffers_iterator<BufferSequence>& e)
{
    assert(b < e);
    typename BufferSequence::value_type v = *b.position().first;
    const char* be = boost::asio::buffer_cast<const char*>(v)
            + boost::asio::buffer_size(v);
    if (b.position().first == e.position().first)
    {
        typename BufferSequence::value_type vv = *e.position().first;
        const char* eb = boost::asio::buffer_cast<const char*>(vv)
                + e.position().second;
        return std::min(be, eb);
    }
    return be;
}

#endif // BUFFER_SEQUENCE_H
