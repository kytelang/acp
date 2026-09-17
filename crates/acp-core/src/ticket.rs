//! Ticketing / ITSM materialisation of a hold (decision F5).
//!
//! When a call is held for approval, some customers want it to appear as a Jira/ServiceNow ticket
//! that an approver resolves in their existing queue. The ticket must carry redacted details only,
//! and resolving it must consume the single-use approval exactly once, so the ticket id becomes
//! part of the presented-context evidence. This models the ticket lifecycle as a strict state
//! machine so a double-resolve or a resolve-after-consume cannot execute the call twice.

/// The lifecycle of a hold ticket. Transitions are one-way; a consumed ticket is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketState {
    Open,
    Approved,
    Denied,
    Consumed,
}

#[derive(Debug, Clone)]
pub struct Ticket {
    pub id: String,
    pub approval_id: String,
    pub summary: String,
    pub state: TicketState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    NotApproved,
    AlreadyResolved,
    AlreadyConsumed,
}

impl Ticket {
    /// Materialise a hold as an open ticket. `summary` must already be redacted by the caller.
    pub fn open(id: &str, approval_id: &str, summary: &str) -> Self {
        Ticket {
            id: id.to_string(),
            approval_id: approval_id.to_string(),
            summary: summary.to_string(),
            state: TicketState::Open,
        }
    }

    pub fn approve(&mut self) -> Result<(), TicketError> {
        match self.state {
            TicketState::Open => {
                self.state = TicketState::Approved;
                Ok(())
            }
            TicketState::Consumed => Err(TicketError::AlreadyConsumed),
            _ => Err(TicketError::AlreadyResolved),
        }
    }

    pub fn deny(&mut self) -> Result<(), TicketError> {
        match self.state {
            TicketState::Open => {
                self.state = TicketState::Denied;
                Ok(())
            }
            TicketState::Consumed => Err(TicketError::AlreadyConsumed),
            _ => Err(TicketError::AlreadyResolved),
        }
    }

    /// Consume the single-use approval that this ticket represents. Only an approved, not-yet-
    /// consumed ticket can be consumed, and only once: the second attempt fails closed.
    pub fn consume(&mut self) -> Result<String, TicketError> {
        match self.state {
            TicketState::Approved => {
                self.state = TicketState::Consumed;
                Ok(self.approval_id.clone())
            }
            TicketState::Consumed => Err(TicketError::AlreadyConsumed),
            _ => Err(TicketError::NotApproved),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approved_ticket_consumes_its_approval_exactly_once() {
        let mut t = Ticket::open("JIRA-1", "ap-9", "held: payments.charge (high)");
        t.approve().unwrap();
        assert_eq!(
            t.consume().unwrap(),
            "ap-9",
            "consuming yields the approval id"
        );
        assert_eq!(
            t.consume(),
            Err(TicketError::AlreadyConsumed),
            "no double execution"
        );
    }

    #[test]
    fn an_unapproved_ticket_cannot_be_consumed() {
        let mut t = Ticket::open("SN-1", "ap-1", "held");
        assert_eq!(t.consume(), Err(TicketError::NotApproved));
    }

    #[test]
    fn a_resolved_ticket_cannot_be_resolved_again() {
        let mut t = Ticket::open("SN-2", "ap-2", "held");
        t.deny().unwrap();
        assert_eq!(t.approve(), Err(TicketError::AlreadyResolved));
    }
}
