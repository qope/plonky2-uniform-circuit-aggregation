pub mod traits;

// StatementのVecを受け取り、それを良い感じに配置する
// 階層が存在する感じ
// [2, 2, 2, 2]だと2*2*2*2 = 16個のステートメントを処理できる
// little edianで処理する.
// 無駄なstatementに関してはproofを使い回して、最後のaggregated proofを利用する段階で切り落とせばよい

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
