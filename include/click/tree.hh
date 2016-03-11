

// A Tree class for Click.
#include <click/vector.hh>

template <class T> 
class Tree {

private:
    Tree<T> parent;
    Vector<Tree<T>> subTrees;
    
public:
    

    int addSubtree(Tree<T> subTree);
    int getSubtree(int i); // get the i-th subtree
    
    int attachLeftmost(T treeItem);
    int attachRightmost(T treeItem);    
    int attachLeftmostSubtree(Tree<T> leftTree);
    int attachRightmostSubtree(Tree<T> rightTree);
    int detachLeftmostSubtree();
    int detachRightmostSubtree();
    


    
};
