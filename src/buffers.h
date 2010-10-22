#if !defined(_BUFFERS_H_)
#define _BUFFERS_H_

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <numeric>
#include <functional>
#include <list>
#include "buffer_iterator.h"

template <int _SIZE>
class chunk
{
  public:
    typedef boost::array<char, _SIZE> container;
    typedef boost::shared_ptr<container> container_ptr;    

    chunk () : cont_ (new container) {}
    chunk (const container_ptr& ptr) : cont_ (ptr) {}

    typename container::value_type* data (void) { return this->cont_->data (); }
    const typename container::value_type* data (void) const { return this->cont_->data (); }
    std::size_t size (void) const { return this->cont_->size (); }

  private:
    template <int, class> friend class sbuffer; 
    container_ptr cont_;
};

template <int _SIZE, class Buffer = boost::asio::mutable_buffer>
class sbuffer
        : private chunk <_SIZE>
        , public Buffer
{
    typedef chunk <_SIZE> base;

  public:
    typedef typename base::container::value_type value_type;
    typedef typename base::container::iterator iterator;
    typedef typename base::container::const_iterator const_iterator;

    sbuffer()
            : base()
            , Buffer(this->base::data(), _SIZE)
    {
    }

    template <class Other>
    sbuffer (const sbuffer<_SIZE, Other>& src)
            : base (src.cont_)
            , Buffer (this->base::data(), _SIZE)
    {
    }    

    iterator begin()
    {
        if (this->base::cont_)
            return this->base::cont_->begin();
        return iterator();
    }

    iterator end()
    {
        if (this->base::cont_)
            return this->base::cont_->end();
        return iterator();
    }

  private:
    sbuffer (const base& cont, std::size_t start)
            : base (cont)
            , Buffer (this->data() + start, std::max<long>(this->base::size() - start, 0))
    {
    } 

    template <int _SZ, class Other>
    friend sbuffer<_SZ, Other> operator+ (const sbuffer<_SZ, Other>& b, std::size_t start);
};

template <int _SIZE, class Buffer> 
inline sbuffer<_SIZE, Buffer> operator+ (const sbuffer<_SIZE, Buffer>& b, std::size_t start) 
{ 
    sbuffer<_SIZE, Buffer> tmp (static_cast<const typename sbuffer<_SIZE, Buffer>::base &>(b), start);
    return tmp;
}

template <int _SIZE, class Buffer> 
inline sbuffer<_SIZE, Buffer> operator+ (std::size_t start, const sbuffer<_SIZE, Buffer>& b) { return boost::asio::operator+(b, start); }

template <int _SIZE> 
class mutable_buffer_list : private std::list<sbuffer<_SIZE, boost::asio::mutable_buffer> >
{
  public:
    typedef sbuffer<_SIZE, boost::asio::mutable_buffer> buffer;
    typedef std::list<buffer> list;

    typedef continious_iterator <
        mutable_buffer_list const, typename list::const_iterator, typename buffer::const_iterator
        > const_iterator;

    typedef continious_iterator <
        mutable_buffer_list, typename list::iterator, typename buffer::iterator
        > iterator;

    iterator begin()
    {
        typename list::iterator lit = this->list::begin();      
        return iterator(this, lit, lit->begin());
    }

    iterator end()
    {
        return iterator(this, this->list::end(), typename buffer::iterator());  
    }

    mutable_buffer_list() 
    { 
        push_back (buffer ()); 
    }

    mutable_buffer_list(const mutable_buffer_list& src) 
            : list (src)
    {
    }

    explicit mutable_buffer_list(const buffer& src)     
    {
        push_back (src);
    }

    // 'it' should point somewhere at the last chunk or at the end of the buffer list
    boost::asio::mutable_buffers_1 tail( iterator& it )
    {
        if ( it == end() )
        {       
            buffer newb;
            push_back(newb);
            typename list::iterator lit = this->list::end();
            lit--;
            it = iterator(this, lit, lit->begin());
            return boost::asio::buffer(newb);
        }
        else
        {
            typename list::iterator lit = this->list::end();
            lit--;
            typename iterator::difference_type diff = it - iterator(this, lit, lit->begin());
            return boost::asio::buffer(*lit + diff);        
        }    
    }

    void release_head( iterator it )
    {
        if (it == end())
        {
            assert(!this->empty());
            this->resize(1);    
            return;
        }

        typename list::iterator lit = this->list::begin();
        while ( lit!=it.iter1_ )
        {
            typename list::iterator saved = lit++;
            erase(saved);
        }
        if (it.iter2_ == it.iter1_->end())
            erase(it.iter1_);
    }

    static std::list< boost::asio::const_buffer > const_buffers( iterator b, iterator e )
    {
        typename iterator::iterator1_t i1 = b.iter1_;
        typename iterator::iterator2_t j1 = b.iter2_;
        typename iterator::iterator1_t i2 = e.iter1_;
        typename iterator::iterator2_t j2 = e.iter2_;
        
        std::list< boost::asio::const_buffer > l;
        if (b == e)
            return l;

        typename iterator::iterator1_t e1;
        if ( b.cont_)
            e1 = b.cont_->end().iter1_;

        while (i1 != i2)
        {
            l.push_back( boost::asio::const_buffer( j1, i1->end() - j1 ) ); 
            if (++i1 != e1)
                j1 = i1->begin();
        }

        if (i1 != e1)
            l.push_back( boost::asio::const_buffer( j1, j2 - j1 ) );

        return l;
    }
};

typedef mutable_buffer_list<16384> mutable_buffers;

#endif // _BUFFERS_H_
