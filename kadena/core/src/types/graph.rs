/// ! THIS MODULE MUST BE UPDATED IF THE CHAIN GRAPH DEGREE CHANGES.
/// !
/// ! The fact that this is a constant means that the code in this and any derived
/// ! module can only be used with headers which have the same chain graph degree.

/// The degree of the chain graph. This the number of adjacent parents for
/// each block header.
pub const TWENTY_CHAIN_GRAPH_DEGREE: usize = 3;
pub const TWENTY_CHAIN_GRAPH_ORDER: usize = 20;

pub type TwentyChainGraphType = 
    [[u16; TWENTY_CHAIN_GRAPH_DEGREE]; TWENTY_CHAIN_GRAPH_ORDER];

pub const TWENTY_CHAIN_GRAPH: TwentyChainGraphType = [
    [10, 15, 5],
    [11, 16, 6],
    [12, 17, 7],
    [13, 18, 8],
    [14, 19, 9],
    [0, 7, 8],
    [1, 8, 9],
    [2, 5, 9],
    [3, 5, 6],
    [4, 6, 7],
    [0, 11, 19],
    [1, 10, 12],
    [11, 13, 2],
    [12, 14, 3],
    [13, 15, 4],
    [0, 14, 16],
    [1, 15, 17],
    [16, 18, 2],
    [17, 19, 3],
    [10, 18, 4],
];