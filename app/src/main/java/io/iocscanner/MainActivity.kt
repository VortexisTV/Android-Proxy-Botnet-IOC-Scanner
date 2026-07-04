package io.iocscanner

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import io.iocscanner.ui.HomeScreen
import io.iocscanner.ui.IocScannerTheme
import io.iocscanner.ui.ResultsScreen
import io.iocscanner.ui.SettingsScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            IocScannerTheme {
                App()
            }
        }
    }
}

enum class Screen { HOME, RESULTS, SETTINGS }

@Composable
fun App(vm: ScanViewModel = viewModel()) {
    var screen by rememberSaveable { mutableStateOf(Screen.HOME) }
    val state by vm.state.collectAsState()

    BackHandler(enabled = screen != Screen.HOME) { screen = Screen.HOME }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        when (screen) {
            Screen.HOME -> HomeScreen(
                state = state,
                onScan = vm::startScan,
                onShowResults = { screen = Screen.RESULTS },
                onShowSettings = { screen = Screen.SETTINGS },
            )
            Screen.RESULTS -> ResultsScreen(
                state = state,
                onRunVt = vm::runVtChecks,
                onCancelVt = vm::cancelVtChecks,
                onExport = vm::exportReport,
                onBack = { screen = Screen.HOME },
            )
            Screen.SETTINGS -> SettingsScreen(
                state = state,
                onSaveKey = vm::saveVtKey,
                onUpdateDb = vm::updateIocDb,
                onResetDb = vm::resetIocDb,
                onBack = { screen = Screen.HOME },
            )
        }
    }
}
