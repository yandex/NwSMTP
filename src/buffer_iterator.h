#ifndef _BUFFER_ITERATOR_H_
#define _BUFFER_ITERATOR_H_
// original version stolen from nikki@

#include <boost/utility.hpp>
#include <boost/iterator/iterator_facade.hpp>
#include <boost/iterator/iterator_traits.hpp>

template <typename Container, typename Iterator1, typename Iterator2>
class continious_iterator
        : public boost::iterator_facade <
    continious_iterator <Container, Iterator1, Iterator2>
    , typename boost::iterator_value<Iterator2>::type
    , boost::forward_traversal_tag // XXX fixme
    >
{
  private:
    struct enabler1 {};
    struct enabler2 {};
    struct enabler3 {};

    typedef Container container_t;
    typedef Iterator1 iterator1_t;
    typedef Iterator2 iterator2_t;

    typedef boost::iterator_facade <
        continious_iterator <Container, Iterator1, Iterator2>
        , typename boost::iterator_value<Iterator2>::type
        , boost::forward_traversal_tag
        > iterator_facade_;

    template <typename C> struct Hack { typedef C type; };
    friend class Hack<Container>::type;


    container_t* cont_;
    iterator1_t iter1_;
    iterator2_t iter2_;

  public:
    continious_iterator ()
            : cont_(0)
            , iter1_ ()
            , iter2_ ()
    {}

    template <typename CC, typename II1, typename II2>
    continious_iterator (
        continious_iterator<CC,II1,II2> const& other
        , typename boost::enable_if<
        boost::is_convertible<CC*,Container*>
        , enabler1
        >::type = enabler1()
        , typename boost::enable_if<
        boost::is_convertible<II1*,Iterator1*>
        , enabler2
        >::type = enabler2()
        , typename boost::enable_if<
        boost::is_convertible<II2*,Iterator2*>
        , enabler3
        >::type = enabler3()
        )
            : cont_(other.cont_)
            , iter1_ (other.iter1_)
            , iter2_ (other.iter2_)
    {}

    typename iterator_facade_::value_type*
    ptr () const // points to the start of the continious chunk 
    {
        return &*iter2_;
    }

    typename iterator_facade_::value_type*
    ptr_end () const // points past the end of the continious chunk 
    {
        return &*iter2_ + (iter1_->end() - iter2_);
    }

    template <typename CC, typename II1, typename II2>
    typename iterator_facade_::value_type*
    ptr_end(  // points past the end of the continious chunk 
        continious_iterator<CC,II1,II2> const& other  
            , typename boost::enable_if<
            boost::is_convertible<CC*,Container*>
            , enabler1
            >::type = enabler1()
            , typename boost::enable_if<
            boost::is_convertible<II1*,Iterator1*>
            , enabler2
            >::type = enabler2()
            , typename boost::enable_if<
            boost::is_convertible<II2*,Iterator2*>
            , enabler3
            >::type = enabler3()
        ) const
    {
        iterator2_t e = (other.iter1_ == iter1_ ? other.iter2_ : iter1_->end());      
        return &*iter2_ + (e - iter2_);
    }

  protected:
    continious_iterator (container_t* c, iterator1_t const& i1, iterator2_t const& i2)
            : cont_(c)
            , iter1_ (i1)
            , iter2_ (i2)
    {}

  private:
    friend class boost::iterator_core_access;

    template <typename CC, typename II1, typename II2>
    typename iterator_facade_::difference_type
    distance_to (
        continious_iterator<CC,II1,II2> const& other
        , typename boost::enable_if<
        boost::is_convertible<CC*,Container*>
        , enabler1
        >::type = enabler1()
        , typename boost::enable_if<
        boost::is_convertible<II1*,Iterator1*>
        , enabler2
        >::type = enabler2()
        , typename boost::enable_if<
        boost::is_convertible<II2*,Iterator2*>
        , enabler3
        >::type = enabler3()
        ) const
    {
        typename iterator_facade_::difference_type diff = 0;
        iterator1_t i1, i2;
        iterator2_t j1, j2;

        i1 = other.iter1_;
        j1 = other.iter2_;
        i2 = iter1_;
        j2 = iter2_;

        while (i1 != i2)
        {
            diff += i1->end () - j1;
            ++i1;       
            j1 = i1->begin();
        }

        iterator1_t e1;
        if (cont_)
            e1 = cont_->end().iter1_;

        if (i2 != e1)
            diff += (j2 - j1);
        assert (diff >= 0);
        return -diff;
    }

    template <typename CC, typename II1, typename II2>
    bool equal (
        continious_iterator<CC,II1,II2> const& other
        , typename boost::enable_if<
        boost::is_convertible<CC*,Container*>
        , enabler1
        >::type = enabler1()
        , typename boost::enable_if<
        boost::is_convertible<II1*,Iterator1*>
        , enabler2
        >::type = enabler2()
        , typename boost::enable_if<
        boost::is_convertible<II2*,Iterator2*>
        , enabler3
        >::type = enabler3()
        ) const
    {
        iterator1_t e1;
        if (cont_)
            e1 = cont_->end().iter1_;
        return (iter1_ == other.iter1_) && 
                ((iter1_ == e1) || (iter2_ == other.iter2_));
    }

    typename iterator_facade_::reference
    dereference () const
    {
        return *iter2_;
    }

    void
    increment ()
    {
        iterator1_t e1;
        if (cont_)
            e1 = cont_->end().iter1_;

        do {
            if (++iter2_ == iter1_->end() &&
                    ++iter1_ != e1)
            {
                iter2_ = iter1_->begin();
            }
        } while ((iter1_ != e1) && 
                (iter2_ == iter1_->end ()));
    }

    void
    advance (typename iterator_facade_::difference_type n)
    {
        typename iterator_facade_::difference_type nn;
        if (n > 0)
        {
            nn = iter1_->end () - iter2_;
            if (nn > n)
            {
                iter2_ += n;
                return;
            }

            n -= nn;      
            ++iter1_;
            iterator1_t e1;
            if (cont_)
                e1 = cont_->end().iter1_;
            while ( (iter1_ != e1) && 
                    (iter1_->end () - iter1_->begin () <= n) 
                    )
            {
                n -= (iter1_->end () - iter1_->begin ());
                ++iter1_;
            }
            if (iter1_ != e1)
                iter2_ = iter1_->begin () + n;
        } 
    }
};


#endif //_BUFFER_ITERATOR_H_
