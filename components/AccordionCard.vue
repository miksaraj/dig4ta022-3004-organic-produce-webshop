<template>
	<b-card no-body>
		<b-card-header role="tab">
			<b-button v-b-toggle="'accordion-' + item.id" block>
				{{ item.header }}
			</b-button>
		</b-card-header>
		<b-collapse
			:id="'accordion-' + item.id"
			accordion="accordion-list"
			role="tabpanel"
		>
			<b-card-body>
				<p>{{ item.description }}</p>
			</b-card-body>
		</b-collapse>
	</b-card>
</template>

<script>
export default {
	name: 'AccordionCard',
	computed: {
		item() {
			return this.$attrs.item
		}
	}
}
</script>
