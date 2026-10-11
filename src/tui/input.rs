use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputAction {
    None,
    Changed,
    Submit,
    Cancel,
}

/// Single-line text field with a cursor, paste support and a length cap.
#[derive(Debug, Clone)]
pub(crate) struct LineInput {
    value: String,
    /// Cursor position in characters, not bytes.
    cursor: usize,
    max_chars: usize,
}

impl LineInput {
    pub(crate) fn new(value: &str, max_chars: usize) -> Self {
        let value: String = value.chars().take(max_chars).collect();
        let cursor = value.chars().count();
        Self {
            value,
            cursor,
            max_chars,
        }
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    pub(crate) fn len(&self) -> usize {
        self.value.chars().count()
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    fn byte_index(&self, chars: usize) -> usize {
        self.value
            .char_indices()
            .nth(chars)
            .map_or(self.value.len(), |(index, _)| index)
    }

    pub(crate) fn insert_str(&mut self, text: &str) -> bool {
        let mut changed = false;
        // Pasted text may contain line breaks or tabs; a single-line field keeps them as spaces.
        for character in text.chars() {
            let character = if character.is_control() {
                ' '
            } else {
                character
            };
            if self.len() >= self.max_chars {
                break;
            }
            let index = self.byte_index(self.cursor);
            self.value.insert(index, character);
            self.cursor += 1;
            changed = true;
        }
        changed
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> InputAction {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => InputAction::Submit,
            KeyCode::Esc => InputAction::Cancel,
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                InputAction::None
            }
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(self.len());
                InputAction::None
            }
            KeyCode::Home => {
                self.cursor = 0;
                InputAction::None
            }
            KeyCode::End => {
                self.cursor = self.len();
                InputAction::None
            }
            KeyCode::Char('a') if control => {
                self.cursor = 0;
                InputAction::None
            }
            KeyCode::Char('e') if control => {
                self.cursor = self.len();
                InputAction::None
            }
            KeyCode::Char('u') if control => {
                let index = self.byte_index(self.cursor);
                self.value.replace_range(..index, "");
                self.cursor = 0;
                InputAction::Changed
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let index = self.byte_index(self.cursor - 1);
                self.value.remove(index);
                self.cursor -= 1;
                InputAction::Changed
            }
            KeyCode::Delete if self.cursor < self.len() => {
                let index = self.byte_index(self.cursor);
                self.value.remove(index);
                InputAction::Changed
            }
            KeyCode::Char(character) if !control => {
                if self.insert_str(character.encode_utf8(&mut [0; 4])) {
                    InputAction::Changed
                } else {
                    InputAction::None
                }
            }
            _ => InputAction::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn edits_in_the_middle_of_cyrillic_text() {
        let mut input = LineInput::new("прокси", 64);
        input.handle_key(key(KeyCode::Left));
        input.handle_key(key(KeyCode::Left));
        input.handle_key(key(KeyCode::Backspace));
        input.handle_key(key(KeyCode::Char('К')));
        assert_eq!(input.value(), "проКси");
        assert_eq!(input.cursor(), 4);
    }

    #[test]
    fn paste_is_single_line_and_capped() {
        let mut input = LineInput::new("", 5);
        input.insert_str("ab\ncdefgh");
        assert_eq!(input.value(), "ab cd");
    }

    #[test]
    fn ctrl_u_clears_before_cursor() {
        let mut input = LineInput::new("https://x", 64);
        input.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(input.value(), "");
    }
}
