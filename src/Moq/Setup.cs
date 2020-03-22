// Copyright (c) 2007, Clarius Consulting, Manas Technology Solutions, InSTEDD.
// All rights reserved. Licensed under the BSD 3-Clause License; see License.txt.

using System;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;

namespace Moq
{
	internal abstract class Setup : ISetup
	{
		private readonly InvocationShape expectation;
		private readonly Mock mock;
		private Flags flags;

		protected Setup(Mock mock, InvocationShape expectation)
		{
			Debug.Assert(expectation != null);
			Debug.Assert(mock != null);

			this.expectation = expectation;
			this.mock = mock;
		}

		public virtual Condition Condition => null;

		public InvocationShape Expectation => this.expectation;

		public LambdaExpression Expression => this.expectation.Expression;

		public bool IsConditional => this.Condition != null;

		public bool IsDisabled => (this.flags & Flags.Disabled) != 0;

		public bool IsVerifiable => (this.flags & Flags.Verifiable) != 0;

		public MethodInfo Method => this.expectation.Method;

		public Mock Mock => this.mock;

		public void Disable()
		{
			this.flags |= Flags.Disabled;
		}

		public abstract void Execute(Invocation invocation);

		public Mock GetInnerMock()
		{
			return this.ReturnsInnerMock(out var innerMock) ? innerMock : throw new InvalidOperationException();
		}

		/// <summary>
		///   Attempts to get this setup's return value without invoking user code
		///   (which could have side effects beyond Moq's understanding and control).
		/// </summary>
		public virtual bool TryGetReturnValue(out object returnValue)
		{
			returnValue = default;
			return false;
		}

		public bool Matches(Invocation invocation)
		{
			return this.expectation.IsMatch(invocation) && (this.Condition == null || this.Condition.IsTrue);
		}

		public bool ReturnsInnerMock(out Mock innerMock)
		{
			if (this.TryGetReturnValue(out var returnValue) && Unwrap.ResultIfCompletedTask(returnValue) is IMocked mocked)
			{
				innerMock = mocked.Mock;
				return true;
			}
			else
			{
				innerMock = null;
				return false;
			}
		}

		public void EvaluatedSuccessfully(Invocation invocation)
		{
			this.Condition?.SetupEvaluatedSuccessfully();
			this.expectation.SetupEvaluatedSuccessfully(invocation);
		}

		public virtual void SetOutParameters(Invocation invocation)
		{
		}

		public override string ToString()
		{
			var expression = this.expectation.Expression;
			var mockedType = expression.Parameters[0].Type;

			var builder = new StringBuilder();
			builder.AppendNameOf(mockedType)
			       .Append(' ')
			       .Append(expression.PartialMatcherAwareEval().ToStringFixed());

			return builder.ToString();
		}

		public virtual MockException TryVerify()
		{
			return this.IsVerifiable ? this.TryVerifyAll() : null;
		}

		public abstract MockException TryVerifyAll();

		public MockException TryVerifyInnerMock(Func<Mock, MockException> verify)
		{
			if (this.ReturnsInnerMock(out var innerMock))
			{
				var error = verify(innerMock);
				if (error?.IsVerificationError == true)
				{
					return MockException.FromInnerMockOf(this, error);
				}
			}

			return null;
		}

		public virtual void Uninvoke()
		{
		}

		public void Verifiable()
		{
			this.flags |= Flags.Verifiable;
		}

		void ISetup.Verify()
		{
			foreach (Invocation invocation in this.mock.MutableInvocations)
			{
				invocation.MarkAsVerifiedIfMatchedBy(setup => setup == this);
			}

			var error = this.IsVerifiable ? this.TryVerify() : this.TryVerifyAll();
			if (error?.IsVerificationError == true)
			{
				throw error;
			}
		}

		[Flags]
		private enum Flags : byte
		{
			Disabled = 1,
			Verifiable = 2,
		}
	}
}
