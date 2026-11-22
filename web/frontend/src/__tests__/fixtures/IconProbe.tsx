import SettingsIcon from '@mui/icons-material/Settings';
import { ThemeProvider, createTheme } from '@mui/material/styles';

export default function IconProbe() {
  return (
    <ThemeProvider theme={createTheme()}>
      <SettingsIcon aria-label="settings" />
    </ThemeProvider>
  );
}
