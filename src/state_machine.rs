use std::cmp;
use std::io;
use std::io::{Read, Write};

pub(crate) enum ProtocolStatus {
    Continue,
    End,
}

pub trait StreamReadParser {
    type Error;

    fn step(&mut self, data: &mut dyn BufReader) -> Result<ProtocolStatus, Self::Error>;

    fn consume(&mut self, data: &mut dyn BufReader) -> Result<(), Self::Error> {
        loop {
            match self.step(data) {
                Ok(ProtocolStatus::Continue) => {}
                Ok(ProtocolStatus::End) => {
                    break;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok(())
    }
}

pub trait StreamWriteParser {
    type Error;

    fn step(&mut self, data: &mut dyn BufWriter) -> Result<ProtocolStatus, Self::Error>;

    fn produce(&mut self, data: &mut dyn BufWriter) -> Result<(), Self::Error> {
        loop {
            match self.step(data) {
                Ok(ProtocolStatus::Continue) => {}
                Ok(ProtocolStatus::End) => {
                    break;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok(())
    }
}

pub trait ProtocolReadParser {
    type State: HasFinal;
    type Error;

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufReader,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>);
    fn take_state(&mut self) -> Self::State;
    fn set_state(&mut self, state: Self::State);
}

impl<T: ProtocolReadParser> StreamReadParser for T {
    type Error = T::Error;

    fn step(&mut self, data: &mut dyn BufReader) -> Result<ProtocolStatus, Self::Error> {
        let state = self.take_state();
        if state.is_final() {
            self.set_state(state);
            return Ok(ProtocolStatus::End);
        }

        let (new_state, result) = self.transition(state, data);
        self.set_state(new_state);

        result
    }
}

pub trait ProtocolWriteParser {
    type State: HasFinal;
    type Error;

    fn transition(
        &mut self,
        state: Self::State,
        data: &mut dyn BufWriter,
    ) -> (Self::State, Result<ProtocolStatus, Self::Error>);
    fn take_state(&mut self) -> Self::State;
    fn set_state(&mut self, state: Self::State);
}

impl<T: ProtocolWriteParser> StreamWriteParser for T {
    type Error = T::Error;

    fn step(&mut self, data: &mut dyn BufWriter) -> Result<ProtocolStatus, Self::Error> {
        let state = self.take_state();
        if state.is_final() {
            self.set_state(state);
            return Ok(ProtocolStatus::End);
        }

        let (new_state, result) = self.transition(state, data);
        self.set_state(new_state);

        result
    }
}

pub trait BufReader: Read {
    fn buf_ref(&mut self) -> &[u8];
}

pub trait BufWriter: Write {
    fn remaining(&self) -> usize;
    /// Advances the buffer cursor as if a write was done, but returns a slice reference
    /// to that buffer, letting the user fill it. This can be used to bypass one copy.
    fn prewrite(&mut self, amount: usize) -> io::Result<&mut [u8]>;
}

pub trait HasFinal {
    fn is_final(&self) -> bool;
}

impl BufReader for &[u8] {
    fn buf_ref(&mut self) -> &[u8] {
        self
    }
}

impl BufWriter for &mut [u8] {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn prewrite(&mut self, amount: usize) -> io::Result<&mut [u8]> {
        let size = cmp::min(amount, self.len());

        let tmp_slice = std::mem::take(self);
        let (used, rest) = tmp_slice.split_at_mut(size);
        *self = rest;

        Ok(used)
    }
}
