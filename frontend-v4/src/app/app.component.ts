import { Component, ChangeDetectionStrategy } from '@angular/core';
import { ShellComponent } from './shell/shell.component';

@Component({
  selector: 'app-root',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ShellComponent],
  template: `<tf-shell />`,
})
export class AppComponent {}
