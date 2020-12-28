#!/usr/bin/python3.6
# encoding:utf-8
from copy import deepcopy
import math


class Stack(object):
    """
    栈类(DS的数据类型)
    """
    
    def __init__(self):
        self.stack = []

    def push(self, v):
        self.stack.append(v)

    def pop(self):
        if self.stack:
            return self.stack.pop(-1)
        else:
            raise LookupError('Stack is empty!')

    def is_empty(self):
        return bool(self.stack)

    def top(self):
        if self.stack:
            return self.stack[-1]
        else:
            raise LookupError('Stack is empty!')

    def find(self, v):
        return v in self.stack


class TreeNode:
    """
    空间树的结点
    """

    global_node_id = 0
    def __init__(self, _inf=0, _sup=0, _parent=None):
        if _parent == None:
            self.level = 1
        else:
            self.level = _parent.level + 1
        self.inf = _inf
        self.sup = _sup # 地址下标上界，例如这个节点如果指示了地址向量数组中[i...j]位置的地址向量，那么inf为i，
                        # sup为j
        self.parent = _parent
        self.childs = []
        TreeNode.global_node_id += 1
        self.node_id = TreeNode.global_node_id  #结点编号（每次产生新结点，自动递增）
        self.diff_delta = 0    #最低的熵不为0的维度(从1开始)
        self.DS = Stack()
        self.TS = []    # 地址向量列表，每个成员代表一个被Expand的地址向量，
                        # 被Expand的维度上值为-1
        self.SS = set() # 扫描过的IPv6地址字符串集合
        self.NDA = 0
        self.AAD = 0.0
        self.last_pop = 0   #记录DS上一次弹出的维度【从1开始】
        self.last_pop_value = 0 # 记录DS上一次弹出的值

    def isLeaf(self):
        return self.childs == []

    def Steady(self, delta, V):
        """
        判断结点中的所有向量序列是否在维度delta上有相同值

        Args：
            delta：待判断维度
            V：所有种子向量序列

        Return：
            same：结点中向量序列在delta维度上熵为0时为True
        """

        v1 = V[self.inf]
        same = True
        for v2 in V[self.inf + 1: self.sup + 1]:
            if v1[delta - 1] != v2[delta - 1]:
                same = False
                break
        return same

    def ExpandTS(self, delta, V):
        """
        对结点的TS做Expand操作

        Args：
            delta：当前需要Expand的维度
            V：种子地址向量列表
        """
    
        if self.TS == []:   # 叶结点的TS初始为对应的地址向量子序列
            for i in range(self.inf, self.sup + 1):
                self.TS.append(deepcopy(V[i]))  # 注意深拷贝，以免修改V中的原有地址

        self.last_pop = delta
        # self.last_pop_value = self.TS[delta - 1]

        # 对TS中需要Expand的地址，令其delta维度上的值为-1
        for v in self.TS:
            # self.last_pop_value.append()
            v[delta - 1] = -1
        # dup_index = []  # TS中重复成员的下标

        # 删去TS中的重复成员
        self.TS = list(set([tuple(v) for v in self.TS]))
        self.TS = [list(v) for v in self.TS]
        # for i in range(len(self.TS) - 1):
        #     if self.TS[i] == self.TS[i + 1]:
        #         dup_index.append(i)
        # for i in dup_index:
        #     self.TS.pop(i)

    def isAbnormal(self, pi=0.9, min_dim=10):
        """
        根据公式(9)判断结点的AAD是否异常，以此作为异常检测的触发条件
        """

        # vec_dim = len(self.TS[0])   # 地址向量维数
        # beta = 2 ** (128/vec_dim)    # 地址向量每一维度的基数
        # TS_dim = 0  # TS中被Expand过的维度个数（文中的dTS）
        # for d in range(vec_dim):
        #     if self.TS[0][d] == -1:
        #         TS_dim += 1
        # if self.AAD > 9.0 and (beta ** )
        pi = 0.9    # AAD的上限
        scale = 2 ** min_dim # TS的规模下限
        vec_dim = len(self.TS[0])   # 地址向量维数
        beta = 2 ** (128/vec_dim)    # 地址向量每一维度的基数
        TS_dim = 0  # TS中被Expand过的维度个数（文中的dTS）
        for d in range(vec_dim):
            if self.TS[0][d] == -1:
                TS_dim += 1

        #   根据原文的式9
        threshold = (pi/(128 * math.log(2, scale) - 1)) * (
            (128.0 * math.log(2, beta) - TS_dim)/TS_dim)

        if self.AAD >= threshold:
            print('[+]Abnormal region detected!')
            return True
        else:
            return False


    def isTSLarge(self):
        """
        在别名检测时，只有TS规模>=2^20的结点才可能被认为有别名前缀
        """

        vec_dim = len(self.TS[0])
        dim_len = 128 / vec_dim # 向量每一维度的二进制位数
        scale = 0
        for dim in range(vec_dim):
            if self.TS[0][dim] == -1:
                scale += dim_len
        # return scale >= 20
        return scale >= 20

    def  OutputNode(self, V):
        """
        输出一个结点的信息

        Args:
            node:当前结点
            V：地址向量序列
        """

        if self.diff_delta == 0:
            print('[leaf]', end = ' ')
        print('Node ID: ',self.node_id)
        print('[+]%d Address(es):' % (self.sup - self.inf + 1))
        for i in range(self.inf, self.sup + 1):
            print(V[i])
        if self.diff_delta != 0:
            print('[+]Lowest variable dim:%d' % self.diff_delta) 
        print('[+]Parent:', end = ' ')
        if self.parent == None:
            print('None')
        else:
            print(self.parent.node_id)
        print('[+]Childs:', end = ' ')
        if self.childs == []:
            print('None')
        else:
            for child in self.childs:
                print(child.node_id, end = ' ')
            print()
        print('[+]DS:')
        print(self.DS.stack)
        print('[+]TS:')
        if self.TS == []:
            print('None')
        else:
            for v in self.TS:
                print(v)
        print('[+]SS:')
        if self.SS == []:
            print('None')
        else:
            for v in self.SS:
                print(v)
        print('[+]NDA:', self.NDA)
        print('\n')


def Intersection(l1, l2):
    """
    计算两个列表的重复成员

    """
    intersection = [v for v in l1 if v in l2]
    return intersection