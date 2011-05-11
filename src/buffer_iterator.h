#ifndef BUFFER_ITERATOR_H
#define BUFFER_ITERATOR_H

#include <cstddef>
#include <boost/assert.hpp>
#include <boost/iterator.hpp>
#include <boost/type_traits/is_convertible.hpp>
#include <boost/type_traits/add_const.hpp>
#include <boost/asio/buffer.hpp>

namespace detail
{
template <bool IsMutable>
struct ybuffers_iterator_types_helper;

template <>
struct ybuffers_iterator_types_helper<false>
{
    typedef boost::asio::const_buffer buffer_type;
    template <typename ByteType>
    struct byte_type
    {
        typedef typename boost::add_const<ByteType>::type type;
    };
};

template <>
struct ybuffers_iterator_types_helper<true>
{
    typedef boost::asio::mutable_buffer buffer_type;
    template <typename ByteType>
    struct byte_type
    {
        typedef ByteType type;
    };
};

template <typename BufferSequence, typename ByteType>
struct ybuffers_iterator_types
{
    enum
    {
        is_mutable = boost::is_convertible<
        typename BufferSequence::value_type, boost::asio::mutable_buffer>::value
    };
    typedef ybuffers_iterator_types_helper<is_mutable> helper;
    typedef typename helper::buffer_type buffer_type;
    typedef typename helper::template byte_type<ByteType>::type byte_type;
};
}

// Modified version of boost::asio::buffers_iterator that imposes an exta requirement on BufferSequence that its const_iterator be random access iterator.
// Luckily, both boost::asio::streambuf::*_sequence_type::const_iterator and ystreambuf::*_sequence_type::const_iterator types meet this requirement.
template <typename BufferSequence>
class ybuffers_iterator : public boost::iterator<
    std::random_access_iterator_tag,
    typename ::detail::ybuffers_iterator_types<
        BufferSequence, char>::byte_type>
{
  private:
    typedef typename ::detail::ybuffers_iterator_types<
      BufferSequence, char>::buffer_type buffer_type;
    typedef typename ::detail::ybuffers_iterator_types<
        BufferSequence, char>::byte_type byte_type;

  public:
    /// Default constructor. Creates an iterator in an undefined state.
    ybuffers_iterator()
            : current_buffer_(),
              current_buffer_position_(0),
              begin_(),
              current_(),
              end_()
    {
    }

    /// Construct an iterator representing the beginning of the buffers' data.
    static ybuffers_iterator begin(const BufferSequence& buffers)
    {
        ybuffers_iterator new_iter;
        new_iter.begin_ = buffers.begin();
        new_iter.current_ = buffers.begin();
        new_iter.end_ = buffers.end();
        while (new_iter.current_ != new_iter.end_)
        {
            new_iter.current_buffer_ = *new_iter.current_;
            if (boost::asio::buffer_size(new_iter.current_buffer_) > 0)
                break;
            ++new_iter.current_;
        }
        return new_iter;
    }

    /// Construct an iterator representing the end of the buffers' data.
    static ybuffers_iterator end(const BufferSequence& buffers)
    {
        ybuffers_iterator new_iter;
        new_iter.begin_ = buffers.begin();
        new_iter.end_ = buffers.end();
        new_iter.current_ = new_iter.end_;

//         if (new_iter.begin_ != new_iter.end_)
//         {
//             new_iter.current_ = new_iter.end_ - 1;
//             new_iter.current_buffer_ = *new_iter.current_;
//             new_iter.current_buffer_position_ = boost::asio::buffer_size(new_iter.current_buffer_);
//         }
//         else
//         {
//             new_iter.current_ = new_iter.end_;
//         }
        return new_iter;
    }

    /// Dereference an iterator.
    byte_type& operator*() const
    {
        return dereference();
    }

    /// Dereference an iterator.
    byte_type* operator->() const
    {
        return &dereference();
    }

    /// Increment operator (prefix).
    ybuffers_iterator& operator++()
    {
        increment();
        return *this;
    }

    /// Increment operator (postfix).
    ybuffers_iterator operator++(int)
    {
        ybuffers_iterator tmp(*this);
        ++*this;
        return tmp;
    }

    /// Decrement operator (prefix).
    ybuffers_iterator& operator--()
    {
        decrement();
        return *this;
    }

    /// Decrement operator (postfix).
    ybuffers_iterator operator--(int)
    {
        ybuffers_iterator tmp(*this);
        --*this;
        return tmp;
    }

    /// Addition operator.
    ybuffers_iterator& operator+=(std::ptrdiff_t difference)
    {
        advance(difference);
        return *this;
    }

    /// Subtraction operator.
    ybuffers_iterator& operator-=(std::ptrdiff_t difference)
    {
        advance(-difference);
        return *this;
    }

    /// Addition operator.
    friend ybuffers_iterator operator+(const ybuffers_iterator& iter,
            std::ptrdiff_t difference)
    {
        ybuffers_iterator tmp(iter);
        tmp.advance(difference);
        return tmp;
    }

    /// Addition operator.
    friend ybuffers_iterator operator+(std::ptrdiff_t difference,
            const ybuffers_iterator& iter)
    {
        ybuffers_iterator tmp(iter);
        tmp.advance(difference);
        return tmp;
    }

    /// Subtraction operator.
    friend ybuffers_iterator operator-(const ybuffers_iterator& iter,
            std::ptrdiff_t difference)
    {
        ybuffers_iterator tmp(iter);
        tmp.advance(-difference);
        return tmp;
    }

    /// Subtraction operator.
    friend std::ptrdiff_t operator-(const ybuffers_iterator& a,
            const ybuffers_iterator& b)
    {
        return b.distance_to(a);
    }

    /// Test two iterators for equality.
    friend bool operator==(const ybuffers_iterator& a, const ybuffers_iterator& b)
    {
        return a.equal(b);
    }

    /// Test two iterators for inequality.
    friend bool operator!=(const ybuffers_iterator& a, const ybuffers_iterator& b)
    {
        return !a.equal(b);
    }

    /// Compare two iterators.
    friend bool operator<(const ybuffers_iterator& a, const ybuffers_iterator& b)
    {
        return (a.current_ < b.current_)
                || ((a.current_ == b.current_)
                        && (a.current_buffer_position_ < b.current_buffer_position_));
    }

    /// Compare two iterators.
    friend bool operator<=(const ybuffers_iterator& a, const ybuffers_iterator& b)
    {
        return !(b < a);
    }

    /// Compare two iterators.
    friend bool operator>(const ybuffers_iterator& a, const ybuffers_iterator& b)
    {
        return b < a;
    }

    /// Compare two iterators.
    friend bool operator>=(const ybuffers_iterator& a, const ybuffers_iterator& b)
    {
        return !(a < b);
    }

    /// Get internal iterators
    std::pair<typename BufferSequence::const_iterator, size_t> position() const
    {
        return std::make_pair(current_, current_buffer_position_);
    }

  private:
    // Dereference the iterator.
    byte_type& dereference() const
    {
        return boost::asio::buffer_cast<byte_type*>(current_buffer_)[current_buffer_position_];
    }

    // Compare two iterators for equality.
    bool equal(const ybuffers_iterator& other) const
    {
        return current_ == other.current_
                && current_buffer_position_ == other.current_buffer_position_;
    }

    // Increment the iterator.
    void increment()
    {
        BOOST_ASSERT(current_ != end_ && "iterator out of bounds");

        // Check if the increment can be satisfied by the current buffer.
        ++current_buffer_position_;
        if (current_buffer_position_ != boost::asio::buffer_size(current_buffer_))
            return;

        // Find the next non-empty buffer.
        ++current_;
        current_buffer_position_ = 0;
        while (current_ != end_)
        {
            current_buffer_ = *current_;
            if (boost::asio::buffer_size(current_buffer_) > 0)
                return;
            ++current_;
        }
    }

    // Decrement the iterator.
    void decrement()
    {
        BOOST_ASSERT((current_buffer_position_ != 0 || current_ != begin_) && "iterator out of bounds");

        // Check if the decrement can be satisfied by the current buffer.
        if (current_buffer_position_ != 0)
        {
            --current_buffer_position_;
            return;
        }

        // Find the previous non-empty buffer.
        typename BufferSequence::const_iterator iter = current_;
        while (iter != begin_)
        {
            --iter;
            buffer_type buffer = *iter;
            std::size_t buffer_size = boost::asio::buffer_size(buffer);
            if (buffer_size > 0)
            {
                current_ = iter;
                current_buffer_ = buffer;
                current_buffer_position_ = buffer_size - 1;
                return;
            }
        }
    }

    // Advance the iterator by the specified distance.
    void advance(std::ptrdiff_t n)
    {
        if (n > 0)
        {
            BOOST_ASSERT(current_ != end_ && "iterator out of bounds");
            for (;;)
            {
                std::ptrdiff_t current_buffer_balance
                        = boost::asio::buffer_size(current_buffer_)
                        - current_buffer_position_;

                // Check if the advance can be satisfied by the current buffer.
                if (current_buffer_balance > n)
                {
                    current_buffer_position_ += n;
                    return;
                }

                // Update position.
                n -= current_buffer_balance;

                // Move to next buffer. If it is empty then it will be skipped on the
                // next iteration of this loop.
                if (++current_ == end_)
                {
                    BOOST_ASSERT(n == 0 && "iterator out of bounds");
                    current_buffer_ = buffer_type();
                    current_buffer_position_ = 0;
                    return;
                }
                current_buffer_ = *current_;
                current_buffer_position_ = 0;
            }
        }
        else if (n < 0)
        {
            std::size_t abs_n = -n;
            for (;;)
            {
                // Check if the advance can be satisfied by the current buffer.
                if (current_buffer_position_ >= abs_n)
                {
                    current_buffer_position_ -= abs_n;
                    return;
                }

                // Update position.
                abs_n -= current_buffer_position_;

                // Check if we've reached the beginning of the buffers.
                if (current_ == begin_)
                {
                    BOOST_ASSERT(abs_n == 0 && "iterator out of bounds");
                    current_buffer_position_ = 0;
                    return;
                }

                // Find the previous non-empty buffer.
                typename BufferSequence::const_iterator iter = current_;
                while (iter != begin_)
                {
                    --iter;
                    buffer_type buffer = *iter;
                    std::size_t buffer_size = boost::asio::buffer_size(buffer);
                    if (buffer_size > 0)
                    {
                        current_ = iter;
                        current_buffer_ = buffer;
                        current_buffer_position_ = buffer_size;
                        break;
                    }
                }
            }
        }
    }

    // Determine the distance between two iterators.
    std::ptrdiff_t distance_to(const ybuffers_iterator& other) const
    {
        std::ptrdiff_t pos_d = other.current_buffer_position_ - current_buffer_position_;
        if (current_ == other.current_)
            return pos_d;

        bool other_less = other.current_ < current_;
        typename BufferSequence::const_iterator a = other_less ? other.current_ : current_;
        const typename BufferSequence::const_iterator& b = other_less ? current_ : other.current_;

        std::ptrdiff_t abs_d = 0;
        while (a != b)
            abs_d += boost::asio::buffer_size(*a++);

        std::ptrdiff_t d = (other_less ? -abs_d : +abs_d);
        d += pos_d;
        return d;
    }

    buffer_type current_buffer_;
    std::size_t current_buffer_position_;
    typename BufferSequence::const_iterator begin_;
    typename BufferSequence::const_iterator current_;
    typename BufferSequence::const_iterator end_;
};

/// Construct an iterator representing the beginning of the buffers' data.
template <typename BufferSequence>
inline ybuffers_iterator<BufferSequence> ybuffers_begin(
    const BufferSequence& buffers)
{
    return ybuffers_iterator<BufferSequence>::begin(buffers);
}

/// Construct an iterator representing the end of the buffers' data.
template <typename BufferSequence>
inline ybuffers_iterator<BufferSequence> ybuffers_end(
    const BufferSequence& buffers)
{
    return ybuffers_iterator<BufferSequence>::end(buffers);
}



#endif // BUFFER_ITERATOR_H
