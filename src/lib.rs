//! deadhop's sweeping wallet: holds the funds of the wallet the payment
//! service watches, and moves them to a fresh address of another wallet once
//! the confirmed balance reaches a threshold, by a simple send, a PayJoin or
//! a CoinJoin.
pub mod chain;
pub mod coinjoin;
pub mod config;
pub mod error;
pub mod keys;
pub mod payjoin;
pub mod run;
pub mod scan;
pub mod state;
pub mod sweep;
pub mod tx;
